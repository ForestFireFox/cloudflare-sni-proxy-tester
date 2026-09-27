#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloudflare SNI Proxy IP Tester - Windows/Ubuntu."""
import argparse, csv, ipaddress, json, os, platform, re, subprocess, sys, threading, time, urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

# ==================== 默认配置（可被 config.ini 覆盖） ====================
DEFAULT_CONFIG_FILE = "./config.ini"

token = ""       # ipinfo token
downloadBytes = 1024 * 1024 * 20
previousCountry = "HK"
hops = 40

DEFAULT_INPUT = "./ip.csv"
DEFAULT_IP_OUTPUT = "./ip.txt"
DEFAULT_CSV_OUTPUT = "{path}/bestips-{date}{num}.csv"
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
TRACEROUTE_TIMEOUT = 35
DEBUG = False
LOG_FILE = None

ONLY_OUTPUT_BEST_ROUTE = False

# 线路缓存：traceroute 结果按 /24 网段缓存到本地文件，避免重复 tracert
ROUTE_CACHE_FILE = "./route_cache.json"
ROUTE_CACHE_PREFIXLEN = 24

# 手工覆盖规则：优先级高于缓存与 traceroute
IP_OVERRIDE_FILE = "./ip_override.json"

# 用户规则：高级线路覆盖普通线路
ROUTE_PREFIX_RULES = {
    "CN2": [("59.43.", 100)],
    "163": [("202.97.", 60)],
    "169": [("219.158.", 70)],
    "ANet": [("218.105.", 80), ("210.", 80)],
    "CMI": [("221.183.", 80)],
    "CMIN2": [("223.120.", 100)],
}
AS_ROUTE_MAP = {
    "4809": "CN2", "4134": "163", "4837": "169",
    "9929": "ANet", "58453": "CMI", "9808": "CMIN2",
}
HIGH_END_ROUTE_NAMES = {"CN2", "CMIN2"}
HIGH_END_ASNS = {"4809", "9929", "9808"}
ROUTE_PRIORITY = {"Unknown": 0, "163": 60, "169": 70, "ANet": 80,
                  "CMI": 80, "CN2": 100, "CMIN2": 100}
COLO_CITY_MAP = {"NRT":"Tokyo","KIX":"Osaka","LAX":"Los Angeles","SJC":"San Jose",
                 "SEA":"Seattle","DFW":"Dallas","IAD":"Washington","ORD":"Chicago",
                 "MIA":"Miami","SIN":"Singapore","AMS":"Amsterdam","FRA":"Frankfurt",
                 "LHR":"London","HKG":"Hong Kong"}
MAINLAND_CN_CODES = {"CN"}

# ==================== 线程安全状态 ====================
print_lock = threading.Lock()
log_lock = threading.Lock()
cache_lock = threading.RLock()
ip_info_cache = {}

# 手工覆盖规则：[(ip_network, {country/city/route/asn/as_name})]
override_networks = []
override_lock = threading.RLock()

# 线路缓存：{cidr_str: {"route":..., "country_seq":[...], "route_asns":[...]}}
route_cache = {}
route_cache_lock = threading.RLock()


# ==================== 日志 ====================
def log(msg):
    """控制台始终打印；仅在 LOG_FILE 非空时写日志文件。"""
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


def valid_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def public_ip(ip):
    try:
        x = ipaddress.IPv4Address(ip)
        return not (x.is_private or x.is_loopback or x.is_link_local or x.is_multicast or x.is_reserved or x.is_unspecified)
    except ValueError:
        return False


def run_command(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
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
    global token, downloadBytes, previousCountry, hops, ONLY_OUTPUT_BEST_ROUTE
    global DEFAULT_INPUT, DEFAULT_IP_OUTPUT, DEFAULT_CSV_OUTPUT, OUTPUT_FOLDER_PATH
    global DEFAULT_THREADS, MAX_IO_THREADS, DEFAULT_SPEED_WORKERS
    global SPEED_TEST_URL, AVAILABILITY_URL, AVAILABILITY_HOST
    global PING_COUNT, PING_TIMEOUT_SEC, CURL_TIMEOUT_SEC, SPEED_TEST_TIMEOUT
    global MAX_LATENCY_MS, MIN_SPEED_MBPS, TRACEROUTE_TIMEOUT, DEBUG, LOG_FILE
    global ROUTE_CACHE_FILE, ROUTE_CACHE_PREFIXLEN, IP_OVERRIDE_FILE

    if "token" in cfg:
        token = str(cfg["token"])
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
    if "hops" in cfg:
        try:
            hops = int(cfg["hops"])
        except Exception:
            pass
    if "ONLY_OUTPUT_BEST_ROUTE" in cfg:
        ONLY_OUTPUT_BEST_ROUTE = bool(cfg["ONLY_OUTPUT_BEST_ROUTE"])
    if "DEFAULT_INPUT" in cfg:
        DEFAULT_INPUT = str(cfg["DEFAULT_INPUT"])
    if "DEFAULT_IP_OUTPUT" in cfg:
        DEFAULT_IP_OUTPUT = str(cfg["DEFAULT_IP_OUTPUT"])
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
    if "TRACEROUTE_TIMEOUT" in cfg:
        try:
            TRACEROUTE_TIMEOUT = int(cfg["TRACEROUTE_TIMEOUT"])
        except Exception:
            pass
    if "DEBUG" in cfg:
        DEBUG = bool(cfg["DEBUG"])
    if "LOG_FILE" in cfg:
        LOG_FILE = cfg["LOG_FILE"]
    if "ROUTE_CACHE_FILE" in cfg:
        ROUTE_CACHE_FILE = str(cfg["ROUTE_CACHE_FILE"])
    if "ROUTE_CACHE_PREFIXLEN" in cfg:
        try:
            ROUTE_CACHE_PREFIXLEN = int(cfg["ROUTE_CACHE_PREFIXLEN"])
        except Exception:
            pass
    if "IP_OVERRIDE_FILE" in cfg:
        IP_OVERRIDE_FILE = str(cfg["IP_OVERRIDE_FILE"])


# ==================== 路径工具 ====================
def _ensure_parent(path):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


def _next_available(path):
    """如果 path 存在，返回在文件名后加 ' (x)' 的不冲突路径。"""
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    for i in range(1, 10000):
        cand = f"{base} ({i}){ext}"
        if not os.path.exists(cand):
            return cand
    return f"{base} ({int(time.time())}){ext}"


def resolve_output_path(template, output_folder, date_str):
    """解析输出路径模板。

    支持 {path} -> output_folder；{date} -> date_str；{num} -> 冲突时填充 " (x)"。
    不含 {path} 的相对路径相对于当前工作目录（主程序启动目录）解析。
    """
    if template is None or str(template).strip() == "":
        return None
    s = str(template)
    if "{path}" in s:
        s = s.replace("{path}", output_folder)
    elif not os.path.isabs(s):
        # 无 {path} 的相对路径 → 相对 CWD
        s = os.path.abspath(s)
    s = s.replace("{date}", date_str)
    s = os.path.normpath(s)

    if "{num}" in s:
        base = s.replace("{num}", "")
        _ensure_parent(base)
        return _next_available(base)
    _ensure_parent(s)
    return s


# ==================== IP Override ====================
def load_ip_override(path):
    """从 JSON 加载手工覆盖规则。

    格式：{ "cidr": {"country":"", "city":"", "route":"", "asn":"", "as_name":""} }
    支持 IPv4/IPv6 CIDR；文件不存在时返回 0，不报错。
    """
    global override_networks
    with override_lock:
        override_networks = []
        if not path or not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] IP覆盖文件加载失败: {e}", file=sys.stderr)
            return 0
        if not isinstance(data, dict):
            print("[!] IP覆盖文件格式错误：顶层必须是对象", file=sys.stderr)
            return 0
        n = 0
        for cidr, ov in data.items():
            if not isinstance(ov, dict):
                continue
            try:
                net = ipaddress.ip_network(str(cidr), strict=False)
            except ValueError:
                print(f"[!] 无效CIDR，已忽略: {cidr}", file=sys.stderr)
                continue
            norm = {
                "country": str(ov.get("country", "") or "").upper(),
                "city": str(ov.get("city", "") or ""),
                "route": str(ov.get("route", "") or ""),
                "asn": str(ov.get("asn", "") or "").replace("AS", "").strip(),
                "as_name": str(ov.get("as_name", "") or ""),
            }
            override_networks.append((net, norm))
            n += 1
        return n


def override_for(ip):
    """返回命中覆盖规则的字段字典；未命中返回 None。"""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    with override_lock:
        for net, data in override_networks:
            if obj in net:
                return dict(data)
    return None


# ==================== 线路缓存 ====================
def ip_segment(ip, prefixlen=ROUTE_CACHE_PREFIXLEN):
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False))
    except ValueError:
        return None


def load_route_cache(path):
    """读取线路缓存；新格式优先使用 country_seq；兼容旧格式（只有 tour）。"""
    with route_cache_lock:
        if not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                n = 0
                for k, v in data.items():
                    if not isinstance(v, dict) or not v.get("route"):
                        continue
                    if isinstance(v.get("country_seq"), list):
                        seq = [str(x).upper() for x in v["country_seq"] if x]
                    elif v.get("tour") and str(v["tour"]) != "None":
                        # 旧格式兼容：tour 已去 CN 且已按当时 target 截断，
                        # 只能近似作为 country_seq 使用。
                        seq = [x.upper() for x in str(v["tour"]).split("→") if x]
                    else:
                        seq = []
                    route_cache[k] = {
                        "route": str(v.get("route", "")),
                        "country_seq": seq,
                        "route_asns": list(v.get("route_asns") or [])
                    }
                    n += 1
                return n
        except Exception as e:
            print(f"[!] 线路缓存加载失败: {e}", file=sys.stderr)
        return 0


def save_route_cache(path):
    with route_cache_lock:
        if not route_cache:
            return
        try:
            _ensure_parent(path)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(route_cache, f, ensure_ascii=False, indent=2, sort_keys=True)
            os.replace(tmp, path)
        except OSError as e:
            print(f"[!] 线路缓存保存失败: {e}", file=sys.stderr)


def cache_lookup(ip):
    seg = ip_segment(ip)
    if not seg:
        return None
    with route_cache_lock:
        entry = route_cache.get(seg)
        return dict(entry) if entry else None


def cache_store(ip, route, country_seq, route_asns):
    """存 country_seq（原始连续去重序列，未按 target 截断）。"""
    if route in (None, "", "Unknown", "Skipped"):
        return
    seg = ip_segment(ip)
    if not seg:
        return
    with route_cache_lock:
        route_cache[seg] = {
            "route": route,
            "country_seq": [str(c).upper() for c in (country_seq or []) if c],
            "route_asns": list(route_asns or [])
        }


# ==================== IPInfo ====================
def ipinfo_lite(ip, timeout=5):
    ov = override_for(ip)
    if ov:
        return {"asn": ov.get("asn", ""), "as_name": ov.get("as_name", ""),
                "country": ov.get("country", "").upper(),
                "city": ov.get("city", ""), "route": ov.get("route", "")}
    with cache_lock:
        if ip in ip_info_cache:
            return dict(ip_info_cache[ip])
    info = {"asn": "", "as_name": "", "country": "", "city": "", "route": ""}
    try:
        req = urllib.request.Request(
            f"https://api.ipinfo.io/lite/{ip}?token={token}",
            headers={"User-Agent": "Cloudflare-SNI-IP-Tester/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
        info.update({
            "asn": str(data.get("asn", "")).upper().replace("AS", "", 1),
            "as_name": str(data.get("as_name", "")),
            "country": str(data.get("country_code", "")).upper(),
            "city": str(data.get("city", "") or "")
        })
    except Exception as e:
        if DEBUG:
            log(f"[DEBUG] IPInfo {ip}: {e}")
    with cache_lock:
        ip_info_cache[ip] = dict(info)
    return info


def ipinfo_city(ip, timeout=5):
    info = ipinfo_lite(ip, timeout)
    if info.get("city"):
        return info
    try:
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip}/json",
            headers={"User-Agent": "Cloudflare-SNI-IP-Tester/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
        if data.get("city"):
            info["city"] = str(data["city"])
        if data.get("country") and not info.get("country"):
            info["country"] = str(data["country"]).upper()
    except Exception as e:
        if DEBUG:
            log(f"[DEBUG] IPInfo city {ip}: {e}")
    with cache_lock:
        ip_info_cache[ip] = dict(info)
    return info


# ==================== CSV ====================
def load_ips(path):
    for enc in ("utf-8-sig", "utf-8", "gb18030", "gbk"):
        try:
            f = open(path, "r", encoding=enc, newline="")
            break
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            print(f"[!] CSV不存在: {path}", file=sys.stderr)
            sys.exit(1)
    else:
        print("[!] 无法读取CSV编码", file=sys.stderr)
        sys.exit(1)

    out = []
    seen = set()
    with f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            print("[!] CSV缺少表头", file=sys.stderr)
            sys.exit(1)
        names = [x.strip().lower() for x in reader.fieldnames]
        ipcol = next((reader.fieldnames[i] for i, n in enumerate(names) if n == "ip"), None)
        ccol = next((reader.fieldnames[i] for i, n in enumerate(names)
                     if n in {"country", "country_code", "cc"}), None)
        citycol = next((reader.fieldnames[i] for i, n in enumerate(names) if n == "city"), None)
        if not ipcol:
            print("[!] CSV中没有ip列", file=sys.stderr)
            sys.exit(1)
        for row in reader:
            ip = (row.get(ipcol) or "").strip()
            if not valid_ip(ip) or ip in seen:
                continue
            seen.add(ip)
            out.append({
                "ip": ip,
                "input_country": (row.get(ccol) or "").strip().upper() if ccol else "",
                "input_city": (row.get(citycol) or "").strip() if citycol else ""
            })
    log(f"[*] 加载 {len(out)} 个唯一IP")
    return out


# ==================== Stage 1 ====================
def availability(ip, timeout=CURL_TIMEOUT_SEC):
    cmd = ["curl", "-sS", "-k",
           "--connect-timeout", str(timeout),
           "--max-time", str(timeout),
           "--resolve", f"{AVAILABILITY_HOST}:443:{ip}",
           AVAILABILITY_URL]
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
            info["cfcountry"] = v.upper()
        elif k == "colo":
            info["colo"] = v.upper()
    return info if info.get("cfcountry") else None


def stage1(items, threads):
    total = len(items)
    done = 0
    out = []
    log(f"\n[*] 第一阶段：可用性，{total} IP，{threads}线程")
    with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="avail") as ex:
        fmap = {ex.submit(availability, x["ip"]): x for x in items}
        for fut in as_completed(fmap):
            x = fmap[fut]
            done += 1
            ip = x["ip"]
            try:
                cf = fut.result()
            except Exception as e:
                cf = None
                progress("availability", done, total, f"{ip} | DROP exception={e}")
            if not cf:
                progress("availability", done, total, f"{ip} | DROP: Cloudflare trace不可用")
                continue
            y = dict(x)
            y.update(cf)
            out.append(y)
            progress("availability", done, total,
                     f"{ip} | PASS cfcountry={y.get('cfcountry', '')} colo={y.get('colo', '-')}")
    log(f"[*] 第一阶段完成：{len(out)}/{total}")
    return out


# ==================== Stage 2 ====================
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
        # 不含 {bytes} 的链接用 --range 限流，避免滥用
        range_args = ["--range", f"0-{max(0, bytes_to_download - 1)}"]

    host = urlparse(url).hostname or "speed.cloudflare.com"
    cmd = ["curl", "-o", null, "-sS", "-w", "%{speed_download}",
           "--connect-timeout", str(CURL_TIMEOUT_SEC),
           "--max-time", str(SPEED_TEST_TIMEOUT)]
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


# ==================== Traceroute ====================
def parse_trace(output, target):
    out = []
    seen = set()
    for line in output.splitlines():
        for cand in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
            if cand != target and public_ip(cand) and cand not in seen:
                seen.add(cand)
                out.append(cand)
                break
    return out


def traceroute_once(ip):
    if platform.system().lower() == "windows":
        cmd = ["tracert", "-d", "-w", "1000", "-h", str(hops), ip]
    else:
        cmd = ["traceroute", "-n", "-w", "2", "-q", "1", "-m", str(hops), ip]
    ok, out = run_command(cmd, TRACEROUTE_TIMEOUT)
    if not ok and platform.system().lower() != "windows" and \
            ("not found" in out.lower() or "no such file" in out.lower()):
        ok, out = run_command(["tracepath", "-n", "-m", str(hops), ip], TRACEROUTE_TIMEOUT)
    return parse_trace(out, ip) if ok else []


# ==================== Route ====================
def route_prefix(ip):
    for route, rules in ROUTE_PREFIX_RULES.items():
        for prefix, _ in rules:
            if ip.startswith(prefix):
                return route
    return None


def route_asn(asn):
    return AS_ROUTE_MAP.get(str(asn).replace("AS", "").strip())


def better(a, b):
    if not b:
        return a
    if not a:
        return b
    return b if ROUTE_PRIORITY.get(b, 0) > ROUTE_PRIORITY.get(a, 0) else a


def route_by_prefix(hops_list):
    r = None
    for ip in hops_list:
        r = better(r, route_prefix(ip))
    return r


def query_hop_asns(hops_list, workers):
    result = {}
    targets = list(dict.fromkeys(hops_list))
    workers = max(1, min(workers, len(targets))) if targets else 1
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="asn") as ex:
        fmap = {ex.submit(ipinfo_lite, ip): ip for ip in targets}
        for fut in as_completed(fmap):
            ip = fmap[fut]
            try:
                result[ip] = fut.result()
            except Exception:
                result[ip] = {}
    return result


def route_by_asn(hops_list, lookup):
    r = None
    for ip in hops_list:
        r = better(r, route_asn(lookup.get(ip, {}).get("asn", "")))
    return r


def extract_country_sequence(hops_list, lookup):
    """从 hops 提取连续去重后的原始 country 序列（保留 CN，不按 target 截断）。

    这是缓存里保存的“线路指纹”，可在任意 target 下重算 tour，避免跨 IP 复用错位。
    """
    raw = []
    for ip in hops_list:
        info = lookup.get(ip) or ipinfo_lite(ip)
        c = (info.get("country") or "").upper()
        if c:
            raw.append(c)
    seq = []
    for c in raw:
        if not seq or seq[-1] != c:
            seq.append(c)
    return seq


def tour_from_sequence(seq, target):
    """用 country 序列和当前 target 实时计算绕路字符串。

    与旧 tour_countries 的展示逻辑保持一致：
    - 去掉中国大陆 CN 节点（中转绕境内 CN 不算绕路）；
    - 在目标国家出现处截断（后面的国家属于目标国内，不算绕路）；
    - 抑制 A-X-A 式的单点 GeoIP 抖动；
    - 未出现任何绕路则返回 "None"。
    """
    target = (target or "").upper()
    seq = [c for c in (seq or []) if c and c not in MAINLAND_CN_CODES]
    if target in seq:
        seq = seq[:seq.index(target)]
    stable = []
    for i, c in enumerate(seq):
        if 0 < i < len(seq) - 1 and seq[i - 1] == seq[i + 1]:
            continue
        if not stable or stable[-1] != c:
            stable.append(c)
    return "→".join(c for c in stable if c != target) or "None"


def tour_countries(hops_list, target, lookup):
    return tour_from_sequence(extract_country_sequence(hops_list, lookup), target)


def analyze_trace(hops_list, target, threads, force_asn=False):
    if not hops_list:
        return "Unknown", "None", {}
    route = route_by_prefix(hops_list)
    lookup = {}
    if route is None and force_asn:
        lookup = query_hop_asns(hops_list, max(1, min(threads, 20)))
        route = route_by_asn(hops_list, lookup) or "Unknown"
    if not lookup:
        lookup = query_hop_asns(hops_list, max(1, min(threads, 20)))
    if route is None:
        route = route_by_asn(hops_list, lookup) or "Unknown"
    return route, tour_countries(hops_list, target, lookup), lookup


def trace_worker(item, threads, skiptr):
    res = dict(item)
    ip = res["ip"]
    info = ipinfo_city(ip)
    country = (info.get("country") or res.get("input_country")
               or res.get("cfcountry") or "").upper()
    city = info.get("city") or res.get("input_city") \
        or COLO_CITY_MAP.get(res.get("colo", ""), res.get("colo", ""))
    res.update(country=country, city=city)
    if skiptr:
        res.update(route="Skipped", tour="None",
                   route_confidence="skipped", traceroute_hops=[])
        return res

    # 1) 手工覆盖优先级最高：命中则直接采用，不走缓存、不做 traceroute
    ov = override_for(ip)
    if ov and ov.get("route"):
        override_asns = [ov["asn"]] if ov.get("asn") else []
        res.update(route=ov["route"],
                   tour="None",
                   route_confidence="override",
                   traceroute_hops=[],
                   route_asns=override_asns)
        return res

    # 2) 其次查本地线路缓存（按 /24 网段），命中则跳过 tracert
    cached = cache_lookup(ip)
    if cached:
        # 用当前 IP 的 country 从 country_seq 重算 tour，
        # 避免把过去某个 target 下的截断结果错用到当前 IP。
        tour = tour_from_sequence(cached.get("country_seq", []), country)
        res.update(route=cached.get("route", "Unknown"),
                   tour=tour,
                   route_confidence="cached",
                   traceroute_hops=[],
                   route_asns=cached.get("route_asns", []))
        return res

    # 3) 都没有 → 实际 traceroute
    hs = traceroute_once(ip)
    route, tour, lookup = analyze_trace(hs, country, threads, False)
    if route == "Unknown":
        time.sleep(0.3)
        hs = traceroute_once(ip)
        route, tour, lookup = analyze_trace(hs, country, threads, False)

    if route == "Unknown" and hs:
        lookup = query_hop_asns(hs, max(1, min(threads, 20)))
        route = route_by_asn(hs, lookup) or "Unknown"
        tour = tour_countries(hs, country, lookup)

    confidence = "high" if route_by_prefix(hs) else ("medium" if route != "Unknown" else "unknown")
    route_asns = sorted({
        str((lookup.get(h, {}) or {}).get("asn", "")).replace("AS", "").strip()
        for h in hs if (lookup.get(h, {}) or {}).get("asn")
    })
    res.update(route=route, tour=tour, route_confidence=confidence,
               traceroute_hops=hs, route_asns=route_asns)

    # 写入缓存：存 country_seq（原始序列，未按 target 截断）
    if hs:
        country_seq = extract_country_sequence(hs, lookup)
    else:
        country_seq = []
    cache_store(ip, route, country_seq, route_asns)
    return res


def stage3(items, threads, skiptr):
    total = len(items)
    done = 0
    out = []
    log(f"\n[*] 第三阶段：{'跳过traceroute' if skiptr else 'traceroute线路分析'}，{total} IP，{threads}线程")
    with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="trace") as ex:
        fmap = {ex.submit(trace_worker, x, threads, skiptr): x for x in items}
        for fut in as_completed(fmap):
            x = fmap[fut]
            done += 1
            ip = x["ip"]
            try:
                r = fut.result()
            except Exception as e:
                r = dict(x)
                r.update(route="Skipped" if skiptr else "Unknown",
                         tour="None", route_confidence="unknown")
                log(f"[traceroute {done}/{total}] {ip} | ERROR {e}")
            out.append(r)
            progress("traceroute", done, total,
                     f"{ip} | route={r.get('route')} tour={r.get('tour')} "
                     f"target={r.get('country')} confidence={r.get('route_confidence')}")
    return out


# ==================== 输出 ====================
def sort_key(r):
    cc = (r.get("cfcountry") or "").upper()
    return (0 if cc == previousCountry.upper() else 1, cc,
            -float(r["speed"]), float(r["latency"]))


def outputs(results, outtxt, outcsv, only_best):
    results = sorted(results, key=sort_key)

    with open(outcsv, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["route", "ip", "cfcountry", "tour", "country", "city", "speed", "latency"])
        for r in results:
            w.writerow([r.get("route", ""), r["ip"], r.get("cfcountry", ""),
                        r.get("tour", "None"), r.get("country", ""), r.get("city", ""),
                        fmt_speed(r["speed"]), fmt_latency(r["latency"])])
    log(f"[*] CSV已保存：{outcsv}")

    lines = []
    rank = 0
    for r in results:
        route = (r.get("route") or "Unknown").strip()
        route_asns = {str(x).replace("AS", "").strip() for x in (r.get("route_asns") or [])}
        is_high_end = route in HIGH_END_ROUTE_NAMES or bool(HIGH_END_ASNS.intersection(route_asns))
        if only_best and not is_high_end:
            continue

        rank += 1
        tour = r.get("tour", "None")
        rd = route if tour == "None" else f"{route}绕" + "、".join(flag(c) for c in tour.split("→"))
        line = f"{r['ip']}#{flag(r.get('country', ''))} ({rd})"
        city = (r.get("city") or "").strip()
        if city:
            line += f" {city}"
        lines.append(line + f" {rank}")

    with open(outtxt, "w", encoding="utf-8-sig") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    log(f"[*] ip.txt已保存：{outtxt}")


# ==================== Main ====================
def main():
    global DEBUG, LOG_FILE, downloadBytes, DEFAULT_INPUT

    # 预解析 -config，用于加载配置文件
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("-config", default=None)
    pre_args, _ = pre.parse_known_args()
    config_path = pre_args.config if pre_args.config else DEFAULT_CONFIG_FILE
    if config_path and not os.path.isabs(config_path):
        config_path = os.path.abspath(config_path)

    cfg = load_config(config_path)
    apply_config(cfg)

    # 完整参数解析
    p = argparse.ArgumentParser(description="Cloudflare SNI Proxy IP Tester")
    p.add_argument("-threads", default=None,
                   help=f"测试延迟/速度的线程数，默认{DEFAULT_THREADS}，可填 max")
    p.add_argument("-i", "--input", default=None,
                   help="输入CSV文件，默认 ./ip.csv")
    p.add_argument("-o", "--output", default=None,
                   help="CSV输出路径（不做 {path}/{date}/{num} 等替换）")
    p.add_argument("-d", "--download-size", type=float, default=None,
                   help="测速文件大小（单位 MB），默认 20")
    p.add_argument("-skiptr", "--skiptr", action="store_true",
                   help="跳过 traceroute 线路分析")
    p.add_argument("-config", default=None,
                   help="配置文件路径，默认 ./config.ini")
    p.add_argument("-log", action="store_true",
                   help="启用日志文件输出（写入 OUTPUT_FOLDER_PATH）")
    p.add_argument("-debug", action="store_true",
                   help="调试模式：显示剔除原因及系统命令输出")
    a = p.parse_args()

    # 应用命令行覆盖（CLI > config > default）
    if a.debug:
        DEBUG = True
    if a.input is not None:
        DEFAULT_INPUT = a.input
    if a.download_size is not None:
        if a.download_size <= 0:
            print("[!] -d 必须大于0", file=sys.stderr)
            sys.exit(2)
        downloadBytes = int(a.download_size * 1024 * 1024)

    threads = parse_threads(a.threads if a.threads is not None else DEFAULT_THREADS)

    if downloadBytes <= 0:
        print("[!] downloadBytes必须大于0", file=sys.stderr)
        sys.exit(2)

    # 准备输出目录（{date} 格式：YYYY-MM-DD）
    date_str = datetime.now().strftime("%Y-%m-%d")
    output_folder = OUTPUT_FOLDER_PATH.replace("{date}", date_str)
    if not os.path.isabs(output_folder):
        output_folder = os.path.abspath(output_folder)
    os.makedirs(output_folder, exist_ok=True)

    # 日志文件：由 -log 或 config 中 LOG_FILE 非空触发；
    # 控制台打印不受影响（在 log() 中始终执行）。
    # 文件名：log-YYYY-MM-DD-HH-MM-SS{num}.log，位置：OUTPUT_FOLDER_PATH
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

    # 解析 ip.txt 输出路径（仅从 config 获取，CLI 不提供此项）
    out_ip = resolve_output_path(DEFAULT_IP_OUTPUT, output_folder, date_str)

    # 解析 CSV 输出路径
    # -o 时按字面使用（不做 {path}/{date}/{num} 替换）
    # 否则从 config 的 DEFAULT_CSV_OUTPUT 解析（支持三个占位符）
    if a.output is not None:
        out_csv = a.output
        if not os.path.isabs(out_csv):
            out_csv = os.path.abspath(out_csv)
        _ensure_parent(out_csv)
    else:
        out_csv = resolve_output_path(DEFAULT_CSV_OUTPUT, output_folder, date_str)

    # 加载手工覆盖规则（优先级最高）
    n_override = load_ip_override(IP_OVERRIDE_FILE)

    # 加载线路缓存（traceroute 命中缓存则跳过实际 tracert）
    n_cache = load_route_cache(ROUTE_CACHE_FILE)

    log("=" * 60)
    log(f"OS={platform.system()} {platform.release()} threads={threads} "
        f"downloadBytes={downloadBytes} skiptr={a.skiptr}")
    log(f"output_folder = {output_folder}")
    log(f"ip_output     = {out_ip}")
    log(f"csv_output    = {out_csv}")
    log(f"log_file      = {LOG_FILE}")
    log(f"ip_override   = {IP_OVERRIDE_FILE}（已加载 {n_override} 条）")
    log(f"route_cache   = {ROUTE_CACHE_FILE}（已加载 {n_cache} 条）")
    log("=" * 60)

    items = load_ips(DEFAULT_INPUT)
    if not items:
        return

    available = stage1(items, threads)
    if not available:
        log("[!] 无可用IP")
        return

    quality = stage2(available, threads, downloadBytes)
    if not quality:
        log("[!] 无IP通过延迟/速度筛选")
        return

    final = stage3(quality, threads, a.skiptr)

    save_route_cache(ROUTE_CACHE_FILE)
    log(f"[*] 线路缓存已保存：{ROUTE_CACHE_FILE}（共 {len(route_cache)} 条）")

    outputs(final, out_ip, out_csv, ONLY_OUTPUT_BEST_ROUTE)
    log(f"[*] 完成：最终 {len(final)} 个IP")


if __name__ == "__main__":
    main()