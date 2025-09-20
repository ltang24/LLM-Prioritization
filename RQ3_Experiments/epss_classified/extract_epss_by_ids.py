#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple

# ========== 配置 ==========
TXT_PATH = Path("/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_top50_sample.txt")

INPUTS = {
    "Monotonic Decrease": Path("/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_monotonic_decrease_20250908_002222.json"),
    "Monotonic Increase": Path("/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_monotonic_increase_20250908_002222.json"),
    "Stable":              Path("/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_stable_20250908_002222.json"),
    "Sudden Change":       Path("/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_sudden_change_20250908_002222.json"),
}

OUT_DIR = Path("/home/xiaoqun/RQ3_Experimants/epss_classified")  # 输出目录
# =========================

CVE_PAT = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

def is_cve(s: str) -> bool:
    return bool(CVE_PAT.match(s.strip()))

def parse_ids_from_txt(txt_path: Path) -> Dict[str, List[str]]:
    """
    从 txt 中解析 4 类别的 CVE 列表
    """
    if not txt_path.exists():
        raise FileNotFoundError(f"ID 列表文件不存在: {txt_path}")

    groups = {
        "Monotonic Decrease": [],
        "Monotonic Increase": [],
        "Stable": [],
        "Sudden Change": [],
    }
    current = None

    with txt_path.open("r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue

            # 切换组
            if s.startswith("#"):
                if "Monotonic Decrease" in s:
                    current = "Monotonic Decrease"
                elif "Monotonic Increase" in s:
                    current = "Monotonic Increase"
                elif "Stable" in s and "Sudden" not in s:
                    current = "Stable"
                elif "Sudden Change" in s:
                    current = "Sudden Change"
                else:
                    current = None
                continue

            # 采集 CVE
            if current and is_cve(s):
                groups[current].append(s.upper())

    # 去重保序
    for k in groups:
        seen = set()
        dedup = []
        for c in groups[k]:
            if c not in seen:
                seen.add(c)
                dedup.append(c)
        groups[k] = dedup

    return groups

# --------- 针对不同 JSON 结构的通用抽取 ---------

def _guess_cve_key(d: Dict[str, Any]) -> str:
    """在字典里猜测 CVE 字段名"""
    for k in d.keys():
        if k.lower() in ("cve", "cve_id", "cveid", "cve_code"):
            return k
    # 兜底：如果某个键值看起来像 CVE，也返回它
    for k, v in d.items():
        if isinstance(v, str) and is_cve(v):
            return k
    return ""

def _extract_history_block(v: Any) -> Any:
    """
    从一条记录的值中，尽量找出 EPSS history；找不到就返回原对象。
    支持以下常见命名：
      - 'epss_history', 'history', 'epssHistory', 'timeseries', 'time_series', 'series', 'scores'
    """
    if isinstance(v, dict):
        for key in ["epss_history", "history", "epssHistory", "timeseries", "time_series", "series", "scores"]:
            if key in v:
                return v[key]
    # 如果是 list（很多是日期-分数点列表），直接返回
    if isinstance(v, list):
        return v
    return v  # 兜底：返回完整对象

def iter_records(data: Any) -> List[Tuple[str, Any]]:
    """
    将输入 JSON 标准化成 [(cve, record_value), ...] 的形式：
      1) 如果是 { "CVE-2025-0001": {...}, "CVE-2025-0002": {...} }
      2) 如果是 [ {"cve":"CVE-XXXX","history":[...]}, {...} ]
      3) 其它嵌套也尽量猜测
    """
    out = []

    # 1) 顶层就是 dict，键就是 CVE
    if isinstance(data, dict):
        # 情况 A：顶层键就是 CVE
        cve_like_keys = [k for k in data.keys() if is_cve(k)]
        if cve_like_keys:
            for k in cve_like_keys:
                out.append((k.upper(), data[k]))
            return out

        # 情况 B：顶层非 CVE，尝试在 value（list/dict）里找
        for v in data.values():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        cve_key = _guess_cve_key(item)
                        if cve_key and is_cve(str(item[cve_key])):
                            out.append((str(item[cve_key]).upper(), item))
            elif isinstance(v, dict):
                cve_key = _guess_cve_key(v)
                if cve_key and is_cve(str(v[cve_key])):
                    out.append((str(v[cve_key]).upper(), v))

    # 2) 顶层是 list
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                cve_key = _guess_cve_key(item)
                if cve_key and is_cve(str(item[cve_key])):
                    out.append((str(item[cve_key]).upper(), item))

    return out

# -----------------------------------------------

def extract_for_group(group_name: str, ids: List[str], input_path: Path, out_dir: Path) -> Path:
    if not input_path.exists():
        raise FileNotFoundError(f"[{group_name}] 输入 JSON 不存在: {input_path}")

    data = json.loads(input_path.read_text(encoding="utf-8"))
    pairs = iter_records(data)  # [(cve, record_val), ...]

    # 做一个索引
    idx: Dict[str, Any] = {}
    for cve, val in pairs:
        idx[cve] = val

    result = {}
    missed = []

    for cve in ids:
        if cve in idx:
            result[cve] = _extract_history_block(idx[cve])
        else:
            missed.append(cve)

    # 输出文件名
    safe_group = group_name.lower().replace(" ", "_")
    out_path = out_dir / f"selected_epss_history_{safe_group}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    # 报告
    print(f"[{group_name}] 目标 {len(ids)} 个，命中 {len(result)} 个，未命中 {len(missed)} 个 -> {out_path}")
    if missed:
        miss_file = out_dir / f"missing_in_{safe_group}.txt"
        miss_file.write_text("\n".join(missed), encoding="utf-8")
        print(f"  未命中清单: {miss_file}")

    return out_path

def main():
    groups = parse_ids_from_txt(TXT_PATH)
    print("已从 txt 解析到：")
    for g, arr in groups.items():
        print(f"  - {g}: {len(arr)} 条")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for gname, in_path in INPUTS.items():
        ids = groups.get(gname, [])
        if not ids:
            print(f"[{gname}] txt 未提供该组的 CVE 列表，跳过。")
            continue
        extract_for_group(gname, ids, in_path, OUT_DIR)

if __name__ == "__main__":
    main()
