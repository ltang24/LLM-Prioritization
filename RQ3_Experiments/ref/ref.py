#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ref.py  —  CVSS reasoning 生成器（增强版）
改动要点：
1) 更稳抓取：完整 headers、重定向、重试、最小文本长度校验
2) 质量闸门：禁止 CVSS 标签/向量；字数与完整度；越权断言检测；失败原因写入 gate_fail_reasons
3) 净化器：若模型输出含 CVSS 标签，先剥离再验收，而不是直接判死
4) CWE 感知兜底：至少支持 CWE-36（绝对路径遍历/任意文件读取），置信度可设为 medium
5) 始终有输出：即使无 Reference 或网页不可用，也会基于描述 + CWE 生成 8 项 reasoning
6) 目录：默认读 /path/to/project/RQ3_Experimants/meta_data ，写 /path/to/project/RQ3_Experimants/ref
"""

import argparse
import copy
import json
import pathlib
import random
import re
import time
from typing import Dict, List, Tuple

import requests
from bs4 import BeautifulSoup

# === 可选：如你本机已安装 g4f ===
try:
    from g4f.client import Client
    HAS_G4F = True
except Exception:
    HAS_G4F = False

# ================== 路径与参数 ==================
DETAIL_ROOT = pathlib.Path("/path/to/project/RQ3_Experimants/meta_data")  # 输入
REF_ROOT    = pathlib.Path("/path/to/project/RQ3_Experimants/ref")        # 输出
REF_ROOT.mkdir(parents=True, exist_ok=True)

MAX_REFS_PER_CVE = 3           # 每个 CVE 最多尝试几个 Reference
MIN_WEB_TEXT_LEN = 500         # 网页正文最小长度
MIN_DESC_LEN_FOR_CONF_MED = 80 # 描述长度达到该值时，兜底置信度可设 medium
MIN_WORDS_PER_METRIC = 40      # 单项最少字数
RETRY_FETCH = 3                # 抓取重试次数
TIMEOUT_SEC = 30

# 8个指标名
METRICS = [
    "Attack_Vector", "Attack_Complexity", "Privileges_Required", "User_Interaction",
    "Scope", "Confidentiality_Impact", "Integrity_Impact", "Availability_Impact"
]

# =================================================
# =============== 工具函数（通用）==================
# =================================================

def fetch_text(url: str) -> Tuple[str, int]:
    """更鲁棒的网页抓取：完整 headers、重定向、重试，并提取正文文本"""
    headers = {
        "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.8",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": "https://www.google.com/",
        "Connection": "keep-alive",
    }
    last_status = 0
    for attempt in range(1, RETRY_FETCH + 1):
        try:
            rsp = requests.get(url, headers=headers, timeout=TIMEOUT_SEC, allow_redirects=True)
            last_status = rsp.status_code
            if rsp.status_code in (200, 304) and len(rsp.text) >= 100:
                html = BeautifulSoup(rsp.text, "html.parser")
                for script in html(["script", "style", "noscript"]):
                    script.decompose()
                text = html.get_text(separator=" ")
                text = re.sub(r"\s+", " ", text).strip()
                return text, rsp.status_code
        except Exception:
            pass
        time.sleep(1.5 * attempt)
    return "", last_status

def strip_cvss_labels(text: str) -> str:
    """剥离 CVSS 标签、向量、等级关键词，保留自然语言内容"""
    if not text:
        return text
    # 向量
    text = re.sub(r'CVSS:[^\n\r]+', ' ', text, flags=re.I)
    # 简写标签 AV/AC/PR/UI/S/C/I/A: X
    text = re.sub(r'\b(AV|AC|PR|UI|S|C|I|A)\s*:\s*[A-Z]+\b', ' ', text)
    # 常见等级词
    text = re.sub(r'\b(None|Low|Medium|High|Critical|Required|Unchanged|Changed|Network|Local|Physical|Adjacent)\b',
                  ' ', text, flags=re.I)
    # 清理多余空白
    return re.sub(r'\s+', ' ', text).strip()

def too_short(text: str, min_words: int = MIN_WORDS_PER_METRIC) -> bool:
    words = re.findall(r'\w+', text or "")
    return len(words) < min_words

def has_cvss_labels(text: str) -> bool:
    if not text:
        return False
    if "CVSS:" in text:
        return True
    if re.search(r'\b(AV|AC|PR|UI|S|C|I|A)\s*:\s*[A-Z]+\b', text):
        return True
    if re.search(r'\b(None|Low|Medium|High|Critical|Required|Unchanged|Changed|Network|Local|Physical|Adjacent)\b', text, re.I):
        return True
    return False

def model_call(prompt: str, timeout: int = 40, temp: float = 0.3) -> str:
    """调用 g4f；若不可用则返回空让兜底生效"""
    if not HAS_G4F:
        return ""
    client = Client()
    models = ["gpt-4o", "llama-3.1-405b", "gemini-pro"]
    for m in models:
        try:
            time.sleep(random.uniform(0.5, 1.5))
            resp = client.chat.completions.create(
                model=m,
                messages=[{"role": "user", "content": prompt}],
                timeout=timeout,
                temperature=temp,
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception:
            continue
    return ""

def parse_json_loose(raw: str) -> dict:
    """宽松解析 JSON：截取 ```json 块；尝试剥壳；失败则返回空 dict"""
    if not raw:
        return {}
    s = raw.strip()
    if "```json" in s:
        try:
            s = s.split("```json", 1)[1].split("```", 1)[0]
        except Exception:
            pass
    elif "```" in s:
        parts = s.split("```")
        if len(parts) >= 3:
            s = parts[1]
    s = s.strip()
    # 尝试小修复
    s = re.sub(r'^{\s*{', '{', s)
    s = re.sub(r'}\s*}$', '}', s)
    try:
        return json.loads(s)
    except Exception:
        return {}

# =================================================
# ============== CWE 感知兜底模板 ==================
# =================================================

DEFAULT_FALLBACK_TEXT = {
    "Attack_Vector": "Based on the provided information only, the vulnerable operation is reachable through the component’s normal input path. An actor can attempt to supply crafted data that flows to the affected code path without requiring special physical proximity.",
    "Attack_Complexity": "No unusual timing or environment constraints are implied beyond providing inputs that reach the vulnerable code. Exploitation relies on typical parsing and handling of supplied data.",
    "Privileges_Required": "Access requirements follow the interface exposure described. If the operation sits behind authentication, an account with ordinary permissions is needed to invoke the flow.",
    "User_Interaction": "Triggering appears to be at the actor’s will once the interface is reachable; no additional human interaction is implied unless a second party must handle content.",
    "Scope": "Effects remain within the component’s authority unless the vulnerable action influences a distinct backend or security boundary, which would extend impact beyond the immediate module.",
    "Confidentiality_Impact": "Information disclosure is plausible if the operation reveals or returns data not intended for the requester, depending on how the system handles and exposes results.",
    "Integrity_Impact": "Data tampering is possible if the vulnerable behavior allows unintended modification of stored content or state; otherwise integrity effects are not presumed.",
    "Availability_Impact": "Repeated triggering or expensive code paths could degrade throughput or lead to service disruption through resource exhaustion.",
}

CWE_TEMPLATES = {
    # CWE-36: Absolute Path Traversal / 任意文件读取（常见：authenticated arbitrary file read）
    "CWE-36": {
        "Attack_Vector":
            "The component accepts a file path provided by a caller and resolves it on the host. An actor who can reach this interface may supply absolute or traversal paths so that normal canonicalization is bypassed and resolution targets files outside the intended directory.",
        "Attack_Complexity":
            "No special preconditions are implied beyond the ability to submit crafted paths. Exploitation relies on insufficient canonicalization or validation during path resolution.",
        "Privileges_Required":
            "The description indicates the operation is available after login or similar session establishment. An account with ordinary access rights is sufficient to invoke the vulnerable file-handling function.",
        "User_Interaction":
            "The vulnerable operation is invoked at the actor’s will once authenticated; no additional human actions are suggested unless a separate user-driven preview/import workflow is required.",
        "Scope":
            "If the service account can read files belonging to other security authorities (system configuration, other services), effects extend across OS-enforced boundaries and thus beyond the immediate application boundary.",
        "Confidentiality_Impact":
            "Successful exploitation discloses arbitrary file contents accessible to the service account, including configuration, logs, secrets, or source files, depending on OS permissions.",
        "Integrity_Impact":
            "The primitive described is read-oriented; direct modification is not implied. Secondary integrity effects depend on implementation details (e.g., caching or metadata side effects).",
        "Availability_Impact":
            "Repeated reads of large or blocking device paths may tie up I/O and worker threads, degrading throughput and potentially causing denial of service.",
    }
}

def build_cwe_fallback(meta: dict) -> Dict[str, dict]:
    desc = meta.get("Description", "") or ""
    refs = meta.get("Reference", []) or []
    cwes = [c for c in (meta.get("ProblemTypes") or []) if str(c).startswith("CWE-")]
    tpl = CWE_TEMPLATES.get(cwes[0], None) if cwes else None
    evidence = {
        "desc_len": len(desc),
        "ref_hint": refs[0] if refs else "",
        "desc_excerpt": desc[:200]
    }
    out = {}
    for m in METRICS:
        text = (tpl.get(m) if tpl else DEFAULT_FALLBACK_TEXT[m])
        conf = "medium" if (tpl or len(desc) >= MIN_DESC_LEN_FOR_CONF_MED) else "low"
        out[m] = {
            f"{m}_Reasoning": text,
            "_provenance": {"origin": "fallback", "confidence": conf},
            "_evidence": evidence
        }
    return out

# =================================================
# ================ 质量闸门（关键）================
# =================================================

def quality_gate(candidate: Dict[str, str], web_supported: bool, extra_notes: List[str]) -> Tuple[bool, List[str]]:
    """
    检查：
    - 结构完整：包含 8 项 key（每项都有 *_Reasoning）
    - 去标签：不得包含 CVSS 标签/向量（先 strip，再检）
    - 字数：每项 >= MIN_WORDS_PER_METRIC
    - 越权：简单检测强断言词（可按需扩展）
    """
    reasons = []
    # 结构
    missing = []
    for m in METRICS:
        if f"{m}_Reasoning" not in candidate or not candidate.get(f"{m}_Reasoning"):
            missing.append(m)
    if missing:
        reasons.append(f"missing_metrics:{','.join(missing)}")

    # 净化+二次检测
    for m in METRICS:
        key = f"{m}_Reasoning"
        if key in candidate and candidate[key]:
            s = strip_cvss_labels(candidate[key])
            candidate[key] = s
            if has_cvss_labels(s):
                reasons.append(f"contains_cvss_labels:{m}")
            if too_short(s):
                reasons.append(f"too_short:{m}")

    # 越权（非常简易，可自行扩展词表）
    BAN = r'\b(always|guarantee|definitely|certainly|undoubtedly)\b'
    for m in METRICS:
        key = f"{m}_Reasoning"
        if key in candidate and candidate[key]:
            if re.search(BAN, candidate[key], flags=re.I):
                reasons.append(f"overclaim:{m}")

    # 通过条件：没有 reasons
    ok = (len(reasons) == 0)
    return ok, reasons + (extra_notes or [])

# =================================================
# ================= 主流程：单条 ===================
# =================================================

def analyze_one_ref(meta: dict, url: str) -> dict:
    """
    针对一个 ref_link 生成 ref_summary：
    1) 抓取网页文本（可失败）
    2) 组织 Prompt 调模型（可失败/为空）
    3) 质量闸门：不通过则 CWE 兜底
    """
    cve = meta.get("CVE Code", "UNKNOWN-CVE")
    desc = meta.get("Description", "") or ""

    # 1) 网页抓取
    page_text, status = ("", 0)
    if url and url != "N/A":
        page_text, status = fetch_text(url)

    web_supported = (len(page_text) >= MIN_WEB_TEXT_LEN)

    # 2) 构造 Prompt
    prompt = f"""Analyze the following vulnerability for CVSS v3.1 Base Metrics and provide detailed reasoning for each metric **without using any CVSS labels or vector tokens**.

CVE: {cve}
Description: {desc}
Web Content (truncated): {page_text[:2000] if page_text else ""}

Return a JSON object with these fields ONLY:
{{
  "Attack_Vector_Reasoning": "... 40+ words ...",
  "Attack_Complexity_Reasoning": "... 40+ words ...",
  "Privileges_Required_Reasoning": "... 40+ words ...",
  "User_Interaction_Reasoning": "... 40+ words ...",
  "Scope_Reasoning": "... 40+ words ...",
  "Confidentiality_Impact_Reasoning": "... 40+ words ...",
  "Integrity_Impact_Reasoning": "... 40+ words ...",
  "Availability_Impact_Reasoning": "... 40+ words ..."
}}

Rules:
- DO NOT output any CVSS vector like "CVSS:3.1/AV:N/..." or labels like "High/Low/None/Required/Unchanged/Changed".
- Provide objective technical reasoning only; avoid overconfident assertions.
- Minimum 40 words per metric.
"""

    model_raw = model_call(prompt) if desc or web_supported else ""
    model_json = parse_json_loose(model_raw)

    # 把模型结果转换为 candidate map
    candidate = {}
    if model_json:
        for m in METRICS:
            k = f"{m}_Reasoning"
            v = model_json.get(k, "")
            if isinstance(v, str):
                candidate[k] = v

    # 3) 质量闸门
    extra_notes = []
    if not web_supported:
        extra_notes.append("insufficient_web_text")

    ok = False
    reasons: List[str] = []
    if candidate:
        ok, reasons = quality_gate(candidate, web_supported, extra_notes)

    summary = {}
    if ok:
        # 模型通过：写 8 项 + provenance
        for m in METRICS:
            summary[m] = {
                f"{m}_Reasoning": candidate[f"{m}_Reasoning"],
                "_provenance": {"origin": "model", "confidence": "medium" if web_supported else "low"},
                "_evidence": {
                    "web_supported": web_supported,
                    "web_status": status,
                    "web_len": len(page_text or ""),
                    "desc_len": len(desc or ""),
                }
            }
        origin_kind = "model"
        fallback_count = 0
        model_count = 8
    else:
        # 模型失败或不完整：CWE 感知兜底
        summary = build_cwe_fallback(meta)
        origin_kind = "fallback"
        fallback_count = 8
        model_count = 0

    # 质量统计
    summary["_summary_quality"] = {
        "completed_metrics": 8,
        "fallback_metrics": fallback_count,
        "model_metrics": model_count,
        "web_supported": web_supported,
        "desc_len": len(desc or ""),
        "gate_fail_reasons": reasons,          # 关键：失败原因写进去
        "note": "labels stripped before gate"  # 说明我们先净化再验收
    }

    # 原始模型回传保留（便于追溯）
    summary["AI_Raw_Response"] = {
        "content": model_raw or "",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "note": "raw model output before cleaning (may include CVSS tokens)"
    }

    return summary

# =================================================
# ================= 批处理：每个 CVE ==============
# =================================================

def process_one_meta(meta_path: pathlib.Path, out_root: pathlib.Path) -> None:
    """
    确保每个 CVE 至少保存一个 ref_summary：
    - 有 Reference：按顺序最多取 MAX_REFS_PER_CVE 条，至少成功 1 条；若都失败，落兜底一条（ref_link=N/A）
    - 无 Reference：直接兜底一条（ref_link=N/A）
    """
    try:
        meta = json.load(open(meta_path, encoding='utf-8'))
    except Exception as e:
        print(f"✗ 元数据读取失败: {meta_path} - {e}")
        return

    cve_code = meta.get("CVE Code", meta_path.stem)
    refs: List[str] = meta.get("Reference") or []
    if not isinstance(refs, list):
        refs = []

    # 输出路径：与 meta 的相对层级一致
    try:
        rel = meta_path.relative_to(DETAIL_ROOT)
        out_path = out_root / rel
    except Exception:
        out_path = out_root / meta_path.name

    out_path.parent.mkdir(parents=True, exist_ok=True)
    results: List[dict] = []

    print(f"[+] 处理 {cve_code}  ({meta_path})")
    used = 0

    if refs:
        for url in refs[:MAX_REFS_PER_CVE]:
            print(f"    - 分析链接: {url}")
            summary = analyze_one_ref(meta, url)
            results.append({
                "ref_link": url,
                "ref_desc": "",
                "ref_summary": summary
            })
            used += 1

    # 如果没有 refs 或完全没有产生条目，则兜底一条
    if used == 0:
        print("    - 无有效 Reference，使用兜底模板")
        summary = analyze_one_ref(meta, "N/A")
        results.append({
            "ref_link": "N/A",
            "ref_desc": "",
            "ref_summary": summary
        })

    # 保存
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"    ✓ 保存: {out_path}")

# =================================================
# ======================= 主函数 ==================
# =================================================

def main():
    parser = argparse.ArgumentParser(description="CVSS reasoning 生成器（增强版）")
    parser.add_argument("--in_dir",  type=str, default=str(DETAIL_ROOT), help="meta 输入目录")
    parser.add_argument("--out_dir", type=str, default=str(REF_ROOT),    help="ref 输出目录")
    parser.add_argument("--limit",   type=int, default=0, help="最多处理多少个文件（0=不限制）")
    args = parser.parse_args()

    in_dir  = pathlib.Path(args.in_dir)
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 递归找 CVE-*.json
    files = sorted(in_dir.rglob("CVE-*.json"))
    if args.limit and args.limit > 0:
        files = files[:args.limit]

    print(f"输入目录: {in_dir}")
    print(f"输出目录: {out_dir}")
    print(f"待处理: {len(files)} 个文件\n")

    for i, mp in enumerate(files, 1):
        print(f"[{i}/{len(files)}]")
        try:
            process_one_meta(mp, out_dir)
        except KeyboardInterrupt:
            print("中断。")
            break
        except Exception as e:
            print(f"✗ 处理失败 {mp}: {e}")

    print("\n全部完成。")

if __name__ == "__main__":
    main()
