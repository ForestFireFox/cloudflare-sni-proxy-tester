#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloudflare IP Tester - Windows/Ubuntu.

自动从 Cloudflare 官方地址获取 IP 段，每个 /24（IPv4）或 /64（IPv6）
测试单元生成一个随机 IP，测试可用性、延迟和下载速度。
输出精简 CSV：colo, country, city, speed, latency, ip。
"""

import argparse
import csv
import ipaddress
import json
import os
import platform
import random
import re
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

from colo_map import COLO_MAP

# ==================== 默认配置 ====================
DEFAULT_CONFIG_FILE = "./config.ini"

# IP 段来源（Cloudflare 官方，支持镜像）
IPV4_SOURCE = "https://www.cloudflare-cn.com/ips-v4/"
IPV6_SOURCE = "https://www.cloudflare-cn.com/ips-v6/"

downloadBytes = 1024 * 1024 * 20
previousCountry = "HK"

DEFAULT_CSV_OUTPUT = "{path}/bestips-{date}{num}.csv"
DEFAULT_IP_OUTPUT = "./ip.txt"
OUTPUT_FOLDER_PATH = "./output/{date}"

DEFAULT_THREADS = 2
MAX_IO_THREADS = 100
DEFAULT_SPEED_WORKERS = 5

SPEED_TEST_URL = "https://speed.cloudflare.com/__down?during=download&bytes={bytes}"
AVAILABILITY_URL = "https://www.cloudflare.com/cdn-cgi/trace"
AVAILABILITY_HOST = "www.cloudflare.com"

PING_COUNT = 4
PING_TIMEOUT_SEC = 2
CURL_TIMEOUT_SEC = 5
SPEED_TEST_TIMEOUT = 20
MAX_LATENCY_MS = 300.0
MIN_SPEED_MBPS = 1.0
DEBUG = False
LOG_FILE = None

# ==================== 线程安全状态 ====================
print_lock = threading.Lock()
log_lock = threading.Lock()


# ==================== 日志 ====================
def log(msg):
    line = f"{datetime.now():%H:%M:%S} {msg}"
    with print_lock:
        print(line, flush=True)
    if LOG_FILE:
        with log_lock:
            try:
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                pass


def progress(stage, done, total, msg):
    log(f"[{stage} {done}/{total}] {msg}")


# ==================== 工具函数 ====================
def run_command(cmd, timeout=10):
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout
        )
        raw = p.stdout or b""
        text = None
        for enc in ("utf-8", "gb18030", "cp936", "big5", "cp1252"):
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                pass
        if text is None:
            text = raw.decode("utf-8", errors="replace")
        if DEBUG:
            log(f"[DEBUG] RC={p.returncode} CMD={' '.join(cmd)} OUT={text[:500]}")
        return p.returncode == 0, text
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def parse_threads(v):
    if str(v).lower() == "max":
        return MAX_IO_THREADS
    try:
        return max(1, int(v))
    except (ValueError, TypeError):
        print(f"[!] 无效线程数 {v}，使用 {DEFAULT_THREADS}", file=sys.stderr)
        return DEFAULT_THREADS


def flag(cc):
    cc = (cc or "").upper()
    if not re.fullmatch(r"[A-Z]{2}", cc):
        return cc
    return "".join(chr(ord(c) + 0x1F1E6 - ord("A")) for c in cc)


def fmt_latency(v):
    return f"{v:.1f}ms"


def fmt_speed(v):
    return f"{v:.1f}MB/s"


def _ensure_parent(path):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


def _next_available(path):
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    for i in range(1, 10000):
        cand = f"{base} ({i}){ext}"
        if not os.path.exists(cand):
            return cand
    return f"{base} ({int(time.time())}){ext}"


def resolve_output_path(template, output_folder, date_str):
    if template is None or str(template).strip() == "":
        return None
    s = str(template)
    if "{path}" in s:
        s = s.replace("{path}", output_folder)
    elif not os.path.isabs(s):
        s = os.path.abspath(s)
    s = s.replace("{date}", date_str)
    s = os.path.normpath(s)

    if "{num}" in s:
        base = s.replace("{num}", "")
        _ensure_parent(base)
        return _next_available(base)
    _ensure_parent(s)
    return s


# ==================== 配置读取 ====================
def strip_comment(line):
    out = []
    quote = None
    esc = False
    for ch in line:
        if esc:
            out.append(ch)
            esc = False
            continue
        if ch == "\\":
            out.append(ch)
            esc = True
            continue
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        else:
            if ch in ("'", '"'):
                quote = ch
                out.append(ch)
            elif ch == "#":
                break
            else:
                out.append(ch)
    return "".join(out)


def parse_config_value(v):
    v = v.strip()
    if v == "":
        return ""
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("none", "null"):
        return None
    if re.fullmatch(r"[0-9+\-*/().\s]+", v):
        try:
            return eval(v, {"__builtins__": None}, {})
        except Exception:
            pass
    return v


def load_config(path):
    cfg = {}
    if not os.path.exists(path):
        print(f"[!] 配置文件不存在: {path}，使用内置默认配置")
        return cfg

    lines = None
    for enc in ("utf-8-sig", "utf-8", "gb18030", "gbk"):
        try:
            with open(path, "r", encoding=enc) as f:
                lines = f.readlines()
            break
        except UnicodeDecodeError:
            continue
        except OSError as e:
            print(f"[!] 读取配置文件失败: {e}")
            return cfg

    if lines is None:
        print("[!] 无法识别配置文件编码，使用内置默认配置")
        return cfg

    for line in lines:
        line = strip_comment(line).strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        if v.endswith(";"):
            v = v[:-1].strip()
        cfg[k] = parse_config_value(v)
    return cfg


def apply_config(cfg):
    global downloadBytes, previousCountry
    global DEFAULT_CSV_OUTPUT, DEFAULT_IP_OUTPUT, OUTPUT_FOLDER_PATH
    global DEFAULT_THREADS, MAX_IO_THREADS, DEFAULT_SPEED_WORKERS
    global SPEED_TEST_URL, AVAILABILITY_URL, AVAILABILITY_HOST
    global PING_COUNT, PING_TIMEOUT_SEC, CURL_TIMEOUT_SEC, SPEED_TEST_TIMEOUT
    global MAX_LATENCY_MS, MIN_SPEED_MBPS, DEBUG, LOG_FILE
    global IPV4_SOURCE, IPV6_SOURCE

    if "DEFAULT_IP_OUTPUT" in cfg:
        DEFAULT_IP_OUTPUT = str(cfg["DEFAULT_IP_OUTPUT"])

    if "downloadBytes" in cfg:
        try:
            downloadBytes = int(cfg["downloadBytes"])
        except Exception:
            pass
    if "previousCountry" in cfg:
        prev = cfg["previousCountry"]
        if prev is None or str(prev).strip() == "":
            previousCountry = "HK"
        else:
            previousCountry = str(prev).strip().upper()
    else:
        previousCountry = "HK"
    if "DEFAULT_CSV_OUTPUT" in cfg:
        DEFAULT_CSV_OUTPUT = str(cfg["DEFAULT_CSV_OUTPUT"])
    if "OUTPUT_FOLDER_PATH" in cfg:
        OUTPUT_FOLDER_PATH = str(cfg["OUTPUT_FOLDER_PATH"])
    if "DEFAULT_THREADS" in cfg:
        try:
            DEFAULT_THREADS = int(cfg["DEFAULT_THREADS"])
        except Exception:
            pass
    if "MAX_IO_THREADS" in cfg:
        try:
            MAX_IO_THREADS = int(cfg["MAX_IO_THREADS"])
        except Exception:
            pass
    if "DEFAULT_SPEED_WORKERS" in cfg:
        try:
            DEFAULT_SPEED_WORKERS = int(cfg["DEFAULT_SPEED_WORKERS"])
        except Exception:
            pass
    if "SPEED_TEST_URL" in cfg:
        SPEED_TEST_URL = str(cfg["SPEED_TEST_URL"])
    if "AVAILABILITY_URL" in cfg:
        AVAILABILITY_URL = str(cfg["AVAILABILITY_URL"])
    if "AVAILABILITY_HOST" in cfg:
        AVAILABILITY_HOST = str(cfg["AVAILABILITY_HOST"])
    if "PING_COUNT" in cfg:
        try:
            PING_COUNT = int(cfg["PING_COUNT"])
        except Exception:
            pass
    if "PING_TIMEOUT_SEC" in cfg:
        try:
            PING_TIMEOUT_SEC = int(cfg["PING_TIMEOUT_SEC"])
        except Exception:
            pass
    if "CURL_TIMEOUT_SEC" in cfg:
        try:
            CURL_TIMEOUT_SEC = int(cfg["CURL_TIMEOUT_SEC"])
        except Exception:
            pass
    if "SPEED_TEST_TIMEOUT" in cfg:
        try:
            SPEED_TEST_TIMEOUT = int(cfg["SPEED_TEST_TIMEOUT"])
        except Exception:
            pass
    if "MAX_LATENCY_MS" in cfg:
        try:
            MAX_LATENCY_MS = float(cfg["MAX_LATENCY_MS"])
        except Exception:
            pass
    if "MIN_SPEED_MBPS" in cfg:
        try:
            MIN_SPEED_MBPS = float(cfg["MIN_SPEED_MBPS"])
        except Exception:
            pass
    if "DEBUG" in cfg:
        DEBUG = bool(cfg["DEBUG"])
    if "LOG_FILE" in cfg:
        LOG_FILE = cfg["LOG_FILE"]
    if "IPV4_SOURCE" in cfg:
        IPV4_SOURCE = str(cfg["IPV4_SOURCE"])
    if "IPV6_SOURCE" in cfg:
        IPV6_SOURCE = str(cfg["IPV6_SOURCE"])


# ==================== IP 段获取与测试 IP 生成 ====================
def fetch_text(url, timeout=15):
    """获取纯文本 URL 内容。"""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Cloudflare-SNI-Proxy-IP-Tester/3.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] 获取 {url} 失败: {e}", file=sys.stderr)
        return ""


def parse_cidrs(text):
    """解析每行一个 CIDR 的纯文本列表。"""
    cidrs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
            cidrs.append(net)
        except ValueError:
            continue
    return cidrs


def generate_test_ips(ip_version=None):
    """从 Cloudflare 官方 IP 段生成测试 IP。

    ip_version: None=同时测试 IPv4 和 IPv6；4=仅 IPv4；6=仅 IPv6
    IPv4：每个 /24 子网生成一个随机主机号（1-254）的 IP。
    IPv6：每个 /64 子网生成一个随机接口标识符的 IP。
    """
    ips = []

    # ---- IPv4 ----
    if ip_version is None or ip_version == 4:
        v4_text = fetch_text(IPV4_SOURCE)
        v4_networks = parse_cidrs(v4_text)
        for net in v4_networks:
            if net.version != 4:
                continue
            # 将网络按 /24 划分
            for subnet in net.subnets(new_prefix=24):
                # 随机主机号 1-254
                host = random.randint(1, 254)
                ip = subnet.network_address + host
                ips.append(str(ip))

    # ---- IPv6 ----
    if ip_version is None or ip_version == 6:
        v6_text = fetch_text(IPV6_SOURCE)
        v6_networks = parse_cidrs(v6_text)
        for net in v6_networks:
            if net.version != 6:
                continue
            # 将网络按 /64 划分（最小测试单元）
            try:
                for subnet in net.subnets(new_prefix=64):
                    # 随机接口标识符（避免全零和广播）
                    base = int(subnet.network_address)
                    rand_part = random.randint(1, (1 << 64) - 2)
                    ip_int = base + rand_part
                    ip = ipaddress.IPv6Address(ip_int)
                    ips.append(str(ip))
            except ValueError:
                # 如果网络小于 /64，直接跳过
                continue

    # 去重并打乱顺序，避免总是测试相同 IP
    ips = list(dict.fromkeys(ips))
    random.shuffle(ips)
    return ips


# ==================== Stage 1: 可用性 ====================
def availability(ip, timeout=CURL_TIMEOUT_SEC):
    """通过 /cdn-cgi/trace 检查可用性，返回 colo 和 loc。"""
    cmd = [
        "curl", "-sS", "-k",
        "--connect-timeout", str(timeout),
        "--max-time", str(timeout),
        "--resolve", f"{AVAILABILITY_HOST}:443:{ip}",
        AVAILABILITY_URL,
    ]
    ok, out = run_command(cmd, timeout + 3)
    if not ok:
        return None
    info = {}
    for line in out.splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "loc":
            info["country"] = v.upper()
        elif k == "colo":
            info["colo"] = v.upper()
    return info if info.get("colo") else None


def stage1(ips, threads):
    total = len(ips)
    done = 0
    out = []
    log(f"\n[*] 第一阶段：可用性，{total} IP，{threads}线程")
    with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="avail") as ex:
        fmap = {ex.submit(availability, ip): ip for ip in ips}
        for fut in as_completed(fmap):
            ip = fmap[fut]
            done += 1
            try:
                cf = fut.result()
            except Exception as e:
                cf = None
                progress("availability", done, total, f"{ip} | DROP exception={e}")
            if not cf:
                progress("availability", done, total, f"{ip} | DROP: trace不可用")
                continue
            out.append({
                "ip": ip,
                "colo": cf.get("colo", ""),
                "country": cf.get("country", ""),
            })
            progress("availability", done, total,
                     f"{ip} | PASS colo={cf.get('colo', '-')} country={cf.get('country', '-')}")
    log(f"[*] 第一阶段完成：{len(out)}/{total}")
    return out


# ==================== Stage 2: 延迟 + 速度 ====================
ms_re = re.compile(r"(?<![\w.])(\d+(?:[.,]\d+)?)\s*ms\b", re.I)


def extract_ms(output):
    vals = []
    for line in output.splitlines():
        low = line.lower()
        if "average" in low or "平均" in line:
            continue
        if re.search(r"(?:time|时间)\s*<\s*1\s*ms\b", line, re.I):
            vals.append(1.0)
        for m in ms_re.finditer(line):
            try:
                v = float(m.group(1).replace(",", "."))
                if 0 <= v <= 600000:
                    vals.append(v)
            except ValueError:
                pass
    return vals


def ping_latency(ip):
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", str(PING_COUNT), "-w", str(PING_TIMEOUT_SEC * 1000), ip]
    else:
        cmd = ["ping", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT_SEC), ip]
    ok, out = run_command(cmd, PING_COUNT * PING_TIMEOUT_SEC + 3)
    vals = extract_ms(out)
    return sum(vals) / len(vals) if vals else None


def speed_test(ip, bytes_to_download):
    null = "NUL" if platform.system().lower() == "windows" else "/dev/null"
    url = SPEED_TEST_URL
    range_args = []
    if "{bytes}" in url:
        url = url.format(bytes=bytes_to_download)
    else:
        range_args = ["--range", f"0-{max(0, bytes_to_download - 1)}"]

    host = urlparse(url).hostname or "speed.cloudflare.com"
    cmd = [
        "curl", "-o", null, "-sS", "-w", "%{speed_download}",
        "--connect-timeout", str(CURL_TIMEOUT_SEC),
        "--max-time", str(SPEED_TEST_TIMEOUT),
    ]
    cmd += range_args
    cmd += ["--resolve", f"{host}:443:{ip}", url]

    ok, out = run_command(cmd, SPEED_TEST_TIMEOUT + 5)
    if not ok:
        return None
    vals = re.findall(r"(?<![\w.])\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(?![\w.])", out.strip())
    try:
        bps = float(vals[-1])
        return bps / (1024 * 1024) if bps > 0 else None
    except (IndexError, ValueError):
        return None


def speed_worker(item, speed_bytes, sem):
    ip = item["ip"]
    latency = ping_latency(ip)
    if latency is None:
        return ip, None, "DROP: ping无有效ms响应"
    if latency > MAX_LATENCY_MS:
        return ip, None, f"DROP: latency {latency:.1f}ms > {MAX_LATENCY_MS:.0f}ms"
    with sem:
        speed = speed_test(ip, speed_bytes)
    if speed is None:
        return ip, None, "DROP: speed test失败"
    if speed < MIN_SPEED_MBPS:
        return ip, None, f"DROP: speed {speed:.1f}MB/s < {MIN_SPEED_MBPS:.1f}MB/s"
    y = dict(item)
    y.update(latency=latency, speed=speed)
    return ip, y, "PASS"


def stage2(items, threads, speed_bytes):
    total = len(items)
    done = 0
    out = []
    speed_workers = max(1, min(DEFAULT_SPEED_WORKERS, threads, total))
    log(f"\n[*] 第二阶段：延迟+速度，{total} IP，任务线程 {threads}，下载并发 {speed_workers}")
    sem = threading.Semaphore(speed_workers)
    with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="speed") as ex:
        fmap = {ex.submit(speed_worker, x, speed_bytes, sem): x for x in items}
        for fut in as_completed(fmap):
            x = fmap[fut]
            done += 1
            ip = x["ip"]
            try:
                _, res, reason = fut.result()
            except Exception as e:
                res = None
                reason = f"DROP: exception={e}"
            if res:
                out.append(res)
                progress("speed/latency", done, total,
                         f"{ip} | PASS latency={fmt_latency(res['latency'])} speed={fmt_speed(res['speed'])}")
            else:
                progress("speed/latency", done, total, f"{ip} | {reason}")
    log(f"[*] 第二阶段完成：{len(out)}/{total}")
    return out


# ==================== 输出 ====================
def sort_key(r):
    cc = (r.get("country") or "").upper()
    return (0 if cc == previousCountry.upper() else 1, cc,
            -float(r["speed"]), float(r["latency"]))


def get_colo_info(colo):
    """根据 colo 代码查询 (country, city)。未命中返回 ("", "")。"""
    if not colo:
        return "", ""
    info = COLO_MAP.get(colo.upper())
    if info:
        return (info.get("country", "") or "",
                info.get("city", "") or "")
    return "", ""


def outputs(results, outcsv, outtxt):
    """输出 CSV 和 ip.txt。"""
    results = sorted(results, key=sort_key)

    # ---- CSV ----
    with open(outcsv, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["colo", "country", "city", "speed", "latency", "ip"])
        for r in results:
            colo = r.get("colo", "")
            country, city = get_colo_info(colo)
            if not country:
                country = r.get("country", "")
            w.writerow([
                colo,
                country,
                city,
                fmt_speed(r["speed"]),
                fmt_latency(r["latency"]),
                r["ip"],
            ])
    log(f"[*] CSV已保存：{outcsv}")

    # ---- ip.txt ----
    lines = []
    rank = 0
    for r in results:
        rank += 1
        colo = r.get("colo", "")
        country, city = get_colo_info(colo)
        if not country:
            country = r.get("country", "")
        label = flag(country)
        # line = f"{r['ip']}#{label} ({colo})" 带机场三字码的格式
        line = f"{r['ip']}#{label}"
        if city:
            line += f" {city}"
        lines.append(line + f" {rank}")

    with open(outtxt, "w", encoding="utf-8-sig") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    log(f"[*] ip.txt已保存：{outtxt}")

# ==================== Main ====================
def main():
    global DEBUG, LOG_FILE, downloadBytes

    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("-config", default=None)
    pre_args, _ = pre.parse_known_args()
    config_path = pre_args.config if pre_args.config else DEFAULT_CONFIG_FILE
    if config_path and not os.path.isabs(config_path):
        config_path = os.path.abspath(config_path)

    cfg = load_config(config_path)
    apply_config(cfg)

    p = argparse.ArgumentParser(description="Cloudflare SNI Proxy IP Tester (Auto IP)")
    p.add_argument("-threads", default=None,
                   help=f"测试延迟/速度的线程数，默认{DEFAULT_THREADS}，可填 max")
    p.add_argument("-o", "--output", default=None,
                   help="CSV输出路径（不做 {path}/{date}/{num} 等替换）")
    p.add_argument("-d", "--download-size", type=float, default=None,
                   help="测速文件大小（单位 MB），默认 20")
    p.add_argument("-config", default=None,
                   help="配置文件路径，默认 ./config.ini")
    p.add_argument("-log", action="store_true",
                   help="启用日志文件输出（写入 OUTPUT_FOLDER_PATH）")
    p.add_argument("-debug", action="store_true",
                   help="调试模式：显示剔除原因及系统命令输出")
    p.add_argument("-v4", action="store_true",
                   help="只测试 IPv4")
    p.add_argument("-v6", action="store_true",
                   help="只测试 IPv6")
    a = p.parse_args()

    if a.debug:
        DEBUG = True
    if a.download_size is not None:
        if a.download_size <= 0:
            print("[!] -d 必须大于0", file=sys.stderr)
            sys.exit(2)
        downloadBytes = int(a.download_size * 1024 * 1024)

    threads = parse_threads(a.threads if a.threads is not None else DEFAULT_THREADS)

    if a.v4 and a.v6:
        print("[!] -v4 与 -v6 不能同时使用", file=sys.stderr)
        sys.exit(2)
    if a.v4:
        ip_version = 4
    elif a.v6:
        ip_version = 6
    else:
        ip_version = None

    if downloadBytes <= 0:
        print("[!] downloadBytes必须大于0", file=sys.stderr)
        sys.exit(2)

    date_str = datetime.now().strftime("%Y-%m-%d")
    output_folder = OUTPUT_FOLDER_PATH.replace("{date}", date_str)
    if not os.path.isabs(output_folder):
        output_folder = os.path.abspath(output_folder)
    os.makedirs(output_folder, exist_ok=True)

    log_enabled = a.log or (
        LOG_FILE is not None
        and LOG_FILE is not False
        and str(LOG_FILE).strip() != ""
    )
    if log_enabled:
        ts = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        log_path = os.path.join(output_folder, f"log-{ts}.log")
        LOG_FILE = _next_available(log_path)
    else:
        LOG_FILE = None

    if a.output is not None:
        out_csv = a.output
        # 解析 ip.txt 输出路径（仅从 config 获取，CLI 不提供此项）
        out_ip = resolve_output_path(DEFAULT_IP_OUTPUT, output_folder, date_str)
        if not os.path.isabs(out_csv):
            out_csv = os.path.abspath(out_csv)
        _ensure_parent(out_csv)
    else:
        out_csv = resolve_output_path(DEFAULT_CSV_OUTPUT, output_folder, date_str)

    log("=" * 60)
    log(f"OS={platform.system()} {platform.release()} threads={threads} "
        f"downloadBytes={downloadBytes}")
    log(f"output_folder = {output_folder}")
    log(f"csv_output    = {out_csv}")
    log(f"log_file      = {LOG_FILE}")
    log(f"ipv4_source   = {IPV4_SOURCE}")
    log(f"ipv6_source   = {IPV6_SOURCE}")
    log(f"ip_output     = {out_ip}")
    log(f"colo_map      = {len(COLO_MAP)} 条")
    log("=" * 60)

  # 生成测试 IP
    log("[*] 正在从 Cloudflare 官方地址获取 IP 段...")
    ips = generate_test_ips(ip_version)
    if not ips:
        log("[!] 未能获取任何 IP，退出")
        return
    ver_label = {None: "IPv4+IPv6", 4: "IPv4", 6: "IPv6"}[ip_version]
    log(f"[*] 共生成 {len(ips)} 个测试 IP（{ver_label}，每 /24 或 /64 各取一个）")

    available = stage1(ips, threads)
    if not available:
        log("[!] 无可用IP")
        return

    quality = stage2(available, threads, downloadBytes)
    if not quality:
        log("[!] 无IP通过延迟/速度筛选")
        return

    outputs(quality, out_csv, out_ip)
    log(f"[*] 完成：最终 {len(quality)} 个IP")


if __name__ == "__main__":
    main()