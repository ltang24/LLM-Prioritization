#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from typing import List, Union

# ==== 输入文件（按你给的路径） ====
FILES = [
    ("Monotonic Decrease", "/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_monotonic_decrease_20250908_002222.json"),
    ("Monotonic Increase", "/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_monotonic_increase_20250908_002222.json"),
    ("Stable",             "/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_stable_20250908_002222.json"),
    ("Sudden Change",      "/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_sudden_change_20250908_002222.json"),
]

# ==== 输出文件（你也可以改成别的路径/文件名） ====
OUTPUT_TXT = "/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_top50_sample.txt"

TOP_K = 50  # 每类最多输出的数量


def extract_ids_from_json(obj: Union[dict, list]) -> List[str]:
    """
    支持两种常见结构：
    1) dict: { "CVE-xxxx": {...}, ... }  -> 取 keys
    2) list: [ {"cve_id": "CVE-xxxx", ...}, ... ] -> 取每项的 cve_id
    其余结构返回空列表
    """
    if isinstance(obj, dict):
        return list(obj.keys())
    if isinstance(obj, list):
        ids = []
        for item in obj:
            if isinstance(item, dict):
                cid = item.get("cve_id") or item.get("CVE") or item.get("id")
                if isinstance(cid, str):
                    ids.append(cid)
        return ids
    return []


def read_top_ids(path: str, k: int) -> List[str]:
    if not os.path.exists(path):
        print(f"[WARN] 文件不存在: {path}")
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[WARN] 读取/解析失败: {path} | {e}")
        return []

    ids = extract_ids_from_json(data)

    # 为了稳定性，按字母序排序后再取前 k 个（避免 dict 顺序不确定）
    ids = sorted(set(ids))
    return ids[:k]


def main():
    os.makedirs(os.path.dirname(OUTPUT_TXT), exist_ok=True)

    lines_out = []
    for label, path in FILES:
        ids = read_top_ids(path, TOP_K)
        lines_out.append(f"# {label} (count={len(ids)})")
        lines_out.extend(ids)
        lines_out.append("")  # 空行分隔

    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_out))

    print(f"✅ 已写出: {OUTPUT_TXT}")
    for label, path in FILES:
        print(f" - {label}: {path}")

if __name__ == "__main__":
    main()
