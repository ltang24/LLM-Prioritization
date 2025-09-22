#!/usr/bin/env python3
"""
extract_all_meta.py
───────────────────
遍历本地 cveList_V5/cves/**/CVE-*.json
→ 抽取精简元数据
→ 保存到  cveList_V5/extract/<year>/<bucket>/<CVE>.json

用法:
    python3 extract_all_meta.py              # 跑全部
"""

import json, pathlib, re, sys, os

# 1) —— 根据你的目录结构修改以下常量即可 ——
REPO_ROOT = pathlib.Path(
    "/home/xiaoqun/security-agent/cyber_data/cveList_V5/cves"
)                        # 官方 JSON 存放处
OUT_ROOT  = pathlib.Path(
    "/home/xiaoqun/security-agent/cyber_data/cveList_V5/extract_meta"
)                        # 精简 meta 输出路径
# -----------------------------------------------------------

def flatten(js: dict) -> dict:
    cna = js["containers"]["cna"]
    desc = next((d["value"] for d in cna["descriptions"]
                 if d["lang"].startswith("en")), "")
    ptypes = [d["description"]
              for p in cna.get("problemTypes", [])
              for d in p.get("descriptions", []) if d["lang"].startswith("en")]
    affected = [
        {"vendor": a.get("vendor", "n/a"),
         "product": a.get("product", "n/a"),
         "versions": [v.get("version", "n/a") for v in a.get("versions", [])]}
        for a in cna.get("affected", [])
    ]
    refs = [r["url"] for r in cna.get("references", [])]
    meta = js["cveMetadata"]
    return {
        "CVE Code"   : meta["cveId"],
        "Published"  : meta.get("datePublished"),
        "Updated"    : meta.get("dateUpdated"),
        "Description": desc or "N/A",
        "ProblemTypes": ptypes or ["N/A"],
        "Affected"   : affected or ["N/A"],
        "Reference"  : refs or "N/A",
    }

def save(flat: dict):
    cve  = flat["CVE Code"]
    year = cve[4:8]
    num  = int(cve.split("-")[2])
    bucket = f"{num:04d}"[0] + "xxx"     # 0001 → 0xxx
    out_dir = OUT_ROOT / year / bucket
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{cve}.json").write_text(json.dumps(flat, indent=2))

def main():
    total = 0
    for src in REPO_ROOT.rglob("CVE-*.json"):
        try:
            save(flatten(json.load(open(src))))
            total += 1
        except Exception as e:
            print(f"[WARN] {src}: {e}")
    print(f"✓ Extracted {total} CVE meta files → {OUT_ROOT}")

if __name__ == "__main__":
    main()
