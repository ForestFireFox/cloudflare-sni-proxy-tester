#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloudflare Colo (IATA) 代码到国家/城市/旗帜的映射表。

首次运行时会从 Netrvin/cloudflare-colo-list 拉取数据并缓存到 colo_map.json。
后续运行直接读取缓存文件，避免重复网络请求。
"""

import json
import os
import urllib.request

COLO_MAP_FILE = "./colo_map.json"
COLO_MAP_URL = "https://raw.githubusercontent.com/Netrvin/cloudflare-colo-list/main/DC-Colos.json"

def load_colo_map():
    """加载 colo 映射表。优先使用本地缓存，不存在则从网络获取并保存。"""
    if os.path.exists(COLO_MAP_FILE):
        try:
            with open(COLO_MAP_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    # 从网络获取
    try:
        req = urllib.request.Request(
            COLO_MAP_URL,
            headers={"User-Agent": "Cloudflare-SNI-Proxy-IP-Tester/3.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
        with open(COLO_MAP_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return data
    except Exception as e:
        print(f"[!] colo 映射表获取失败: {e}，将使用空映射")
        return {}


# 全局映射表，供主脚本导入
COLO_MAP = load_colo_map()