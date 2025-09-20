#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE 报告生成（综合 ref 向量要点 + 反抄袭 + 多模型回退 + 防空写）

依赖：
  conda activate py310
  pip install g4f beautifulsoup4 requests
"""

import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Tuple, Set

from g4f.client import Client

# ===================== 常量与模板 =====================

DEFAULT_MODEL_CHAIN = [
    "gpt-4o",
    "gpt-4o-mini",
    "claude-3.5-sonnet",
    "gemini-pro",
    "llama-3.1-70b",
]

MAX_RETRIES_PER_MODEL = 2
RATE_LIMIT_KEYWORDS = ["限流", "rate limit", "daily limit", "quota", "battle mode",
                       "please come back later", "too many requests", "try again", "wait"]

# 每个向量最多纳入多少条摘录 & 每条摘录最大长度（避免 prompt 过长）
MAX_SNIPPETS_PER_VECTOR = 6
MAX_CHARS_PER_SNIPPET = 420

# 反抄袭阈值（5-gram 重合率超过此阈值则触发一次重写）
PLAGIARISM_THRESHOLD = 0.22

VECTORS = [
    "Attack_Vector", "Attack_Complexity", "Privileges_Required", "User_Interaction",
    "Scope", "Confidentiality_Impact", "Integrity_Impact", "Availability_Impact"
]

PROMPT_TMPL = r"""SYSTEM:
You are a senior cybersecurity threat intelligence analyst. Write ONE continuous paragraph (600–800 words) in professional threat-intel style. Synthesize from the materials below, but DO NOT copy sentences verbatim. Paraphrase and integrate insights in your own words. Include:
1) concise vulnerability and affected products; 2) technical root cause and exploitation mechanism; 3) CVSS risk implications (no scores or metric labels); 4) attack vector & complexity analysis; 5) realistic exploitation scenarios; 6) mitigation & remediation guidance; 7) confidence assessment. 
Strict rules: No bullet lists, no headings, no line breaks; do NOT output numeric CVSS scores or vector labels (e.g., “8.8”, “AV:N/AC:L/...”, “High/Low/None/Changed/Unchanged”, etc.). Use descriptive language only.

USER:
You are given: (A) CVE metadata, (B) reference descriptions, (C) synthesized vector notes from multiple references for 8 CVSS base metrics. These vector notes are only hints; do not quote or copy them. Re-express in your own words and produce a cohesive single paragraph.

(A) Metadata JSON:
{meta_json}

(B) Reference Descriptions (free text, optional):
{ref_desc_block}

(C) Synthesized Vector Notes (multiple sources, trimmed; for reference only):
{vector_notes_json}

Now write the required single paragraph. Do not copy; do not use CVSS labels or scores.
"""

REWRITE_APPENDIX = (
    "\n\nIMPORTANT ADDENDUM: Your previous output overlapped too much with the reference text. "
    "Rewrite with different phrasing and sentence structure, vary terminology, and avoid any verbatim fragments. "
    "Preserve the technical meaning while fully rewording."
)

# ===================== 实用函数 =====================

def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def normalize_text(s: str) -> str:
    s = re.sub(r"\s+", " ", s or "").strip()
    return s

def unique_keep_order(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        k = normalize_text(x)
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out

def safe_get_reasoning(obj: dict) -> List[str]:
    """从 {Vector: {Vector_Reasoning: "..."} } 结构中提取文本。"""
    out = []
    if not isinstance(obj, dict):
        return out
    for k, v in obj.items():
        if isinstance(v, dict):
            for rk, rv in v.items():
                if isinstance(rv, str) and rk.endswith("_Reasoning") and rv.strip():
                    out.append(rv.strip())
    return out

def gather_vector_notes(ref_entries: List[dict]) -> Dict[str, List[str]]:
    """汇总 8 向量的 Reasoning 文本，去重、截断、限量。"""
    bag: Dict[str, List[str]] = {v: [] for v in VECTORS}
    for entry in ref_entries:
        ref_summary = entry.get("ref_summary") or {}
        if not isinstance(ref_summary, dict):
            continue
        for vec in VECTORS:
            if vec in ref_summary and isinstance(ref_summary[vec], dict):
                for rk, rv in ref_summary[vec].items():
                    if isinstance(rv, str) and rk.endswith("_Reasoning"):
                        txt = normalize_text(rv)[:MAX_CHARS_PER_SNIPPET]
                        if txt:
                            bag[vec].append(txt)
    for vec in VECTORS:
        bag[vec] = unique_keep_order(bag[vec])[:MAX_SNIPPETS_PER_VECTOR]
    return bag

def collect_ref_descs(ref_entries: List[dict], limit: int = 8) -> List[str]:
    descs = []
    for e in ref_entries:
        d = normalize_text(e.get("ref_desc") or "")
        if d:
            descs.append(d)
    return unique_keep_order(descs)[:limit]

def make_ref_desc_block(ref_descs: List[str]) -> str:
    return "(none)" if not ref_descs else " ; ".join(ref_descs)

def extract_cve_info_from_meta(meta: dict) -> Tuple[str, str]:
    cve_id = meta.get("CVE Code") or meta.get("cveMetadata", {}).get("cveId") or "UNKNOWN"
    desc = meta.get("Description") or meta.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value", "")
    return cve_id, desc

def ngram_tokens(text: str, n: int = 5) -> Set[str]:
    text = re.sub(r"\s+", " ", (text or "").lower()).strip()
    words = text.split()
    toks = set()
    for i in range(len(words) - n + 1):
        toks.add(" ".join(words[i:i+n]))
    return toks

def plagiarism_ratio(report: str, evidence_corpus: str, n: int = 5) -> float:
    a = ngram_tokens(report, n)
    b = ngram_tokens(evidence_corpus, n)
    if not a or not b:
        return 0.0
    inter = len(a & b)
    denom = max(1, min(len(a), len(b)))
    return inter / denom

def format_single_paragraph(report_text: str) -> str:
    t = re.sub(r"\*\*([^*]+)\*\*", r"\1", report_text or "")
    t = re.sub(r"`{1,3}.*?`{1,3}", "", t, flags=re.DOTALL)
    t = re.sub(r"\s+", " ", t).strip()
    for kw in ["Summary:", "Mitigation:", "Exploitation:", "CVSS:", "Vector:"]:
        t = t.replace(kw, "")
    words, lines, cur = t.split(), [], ""
    for w in words:
        cand = (cur + " " + w).strip()
        if len(cand) <= 80:
            cur = cand
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return "\n".join(lines)

def shorten_json_for_prompt(obj: dict, max_chars: int) -> str:
    """把 JSON 转成字符串后截断，尽量避免超长 prompt 触发短回复。"""
    s = json.dumps(obj, ensure_ascii=False, indent=2)
    if len(s) > max_chars:
        s = s[:max_chars] + "...(truncated)"
    return s

# ===================== g4f 调用 =====================

def ask_g4f_with_chain(prompt: str, model_chain: List[str], timeout: int, temp: float, min_chars: int, verbose: bool=False) -> Tuple[str, str]:
    """
    轮询模型链直到拿到 >= min_chars 的结果。
    返回 (content, used_model)；都失败时返回 ("", "")。
    """
    client = Client()
    for model in model_chain:
        for attempt in range(1, MAX_RETRIES_PER_MODEL + 1):
            try:
                if verbose:
                    print(f"  [LLM] 模型={model} 尝试 {attempt}/{MAX_RETRIES_PER_MODEL} ...")
                t0 = time.time()
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    timeout=timeout,
                    temperature=temp,
                )
                content = (resp.choices[0].message.content or "").strip()
                dur = time.time() - t0
                if verbose:
                    print(f"  [LLM] 耗时 {dur:.1f}s，长度 {len(content)}")

                low = content.lower()
                if any(k in low for k in RATE_LIMIT_KEYWORDS):
                    if verbose:
                        print("  [LLM] 疑似限流，稍等后重试")
                    time.sleep(8)
                    continue

                if len(content) < min_chars:
                    if verbose:
                        print(f"  [LLM] 内容过短(<{min_chars})，重试/换模")
                    time.sleep(2)
                    continue

                return content, model

            except KeyboardInterrupt:
                raise
            except Exception as e:
                if verbose:
                    print(f"  [LLM] 错误：{e}")
                time.sleep(3)
                continue
        # 下一个模型
    return "", ""

# ===================== Prompt 构建 =====================

def build_prompt(meta: dict, ref_entries: List[dict], max_meta_chars: int, max_notes_chars: int) -> Tuple[str, str]:
    ref_descs = collect_ref_descs(ref_entries, limit=10)
    ref_desc_block = make_ref_desc_block(ref_descs)
    vector_notes = gather_vector_notes(ref_entries)

    meta_json = shorten_json_for_prompt(meta, max_meta_chars)
    notes_json = shorten_json_for_prompt(vector_notes, max_notes_chars)

    prompt = PROMPT_TMPL.format(
        meta_json=meta_json,
        ref_desc_block=ref_desc_block,
        vector_notes_json=notes_json,
    )

    notes_flat = " ".join([" ".join(vector_notes.get(v, [])) for v in VECTORS])
    evidence_corpus = (ref_desc_block + " " + notes_flat).strip()
    return prompt, evidence_corpus

# ===================== 本地兜底（可选） =====================

def local_fallback_paragraph(meta: dict, ref_entries: List[dict]) -> str:
    """不依赖 LLM 的单段落兜底（避免空文件），约 350–600 词。"""
    cve, desc = extract_cve_info_from_meta(meta)
    vector_notes = gather_vector_notes(ref_entries)

    # 取每个向量的第一条简洁要点，改写成非模板式表达
    def first_note(vec):
        arr = vector_notes.get(vec, [])
        return arr[0] if arr else ""

    pieces = []
    if desc:
        pieces.append(f"{cve} concerns a vulnerability described in available metadata as: {desc}.")
    # 利用各向量要点做“解释式”表达，避免照抄
    for vec in VECTORS:
        note = first_note(vec)
        if not note:
            continue
        label = vec.replace("_", " ").lower()
        # 简短改写包裹
        pieces.append(f"Regarding {label}, analysis indicates that {note}")

    text = " ".join(pieces)
    text = re.sub(r"\s+", " ", text).strip()
    # 收尾风险/缓解/信心
    text += " From a risk perspective, the practical attack surface and operational preconditions should be assessed within each deployment to gauge the plausibility of abuse and potential business impact; operators should prioritize vendor patches or configuration hardening that removes the vulnerable code path, enforce least-privilege, tighten input handling, and increase monitoring around suspicious access to sensitive resources. This fallback summary is derived from structured notes and should be treated as provisional when compared with a full narrative written by a large language model."
    return format_single_paragraph(text)

# ===================== 主处理 =====================

def process_one(
    meta_path: Path,
    ref_path: Path,
    out_dir: Path,
    model_chain: List[str],
    timeout: int,
    temp: float,
    min_chars: int,
    plagiarism_threshold: float,
    verbose: bool,
    enable_local_fallback: bool,
    max_meta_chars: int,
    max_notes_chars: int,
) -> dict:

    meta = read_json(meta_path)
    cve_id, _ = extract_cve_info_from_meta(meta)

    if not ref_path.exists():
        return {"cve": cve_id, "status": "failed", "reason": "ref_missing"}

    try:
        ref_entries = json.loads(ref_path.read_text(encoding="utf-8"))
        if not isinstance(ref_entries, list):
            return {"cve": cve_id, "status": "failed", "reason": "ref_not_list"}
    except Exception as e:
        return {"cve": cve_id, "status": "failed", "reason": f"ref_json_error: {e}"}

    # 构建 Prompt
    prompt, evidence_corpus = build_prompt(meta, ref_entries, max_meta_chars, max_notes_chars)

    # 询问模型（链式）
    report, used_model = ask_g4f_with_chain(
        prompt=prompt,
        model_chain=model_chain,
        timeout=timeout,
        temp=temp,
        min_chars=min_chars,
        verbose=verbose,
    )

    if not report:
        if enable_local_fallback:
            if verbose:
                print("  [Fallback] LLM 失败，启用本地兜底生成。")
            final_text = local_fallback_paragraph(meta, ref_entries)
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{meta_path.stem}_enhanced_report.txt"
            out_path.write_text(final_text, encoding="utf-8")
            return {"cve": cve_id, "status": "fallback", "output": str(out_path), "chars": len(final_text)}
        return {"cve": cve_id, "status": "failed", "reason": "llm_empty_or_short"}

    # 反抄袭
    ratio = plagiarism_ratio(report, evidence_corpus, n=5)
    if verbose:
        print(f"  [Guard] 5-gram 重合率: {ratio:.3f} (阈值 {plagiarism_threshold})")

    if ratio >= plagiarism_threshold:
        if verbose:
            print("  [Guard] 触发重写")
        # 重写时升温一点
        report2, _ = ask_g4f_with_chain(
            prompt=prompt + REWRITE_APPENDIX,
            model_chain=[used_model] + [m for m in model_chain if m != used_model],
            timeout=timeout,
            temp=max(0.6, temp),
            min_chars=min_chars,
            verbose=verbose,
        )
        if report2:
            report = report2

    final_text = format_single_paragraph(report)

    # 再做一轮长度闸门，防空写
    if len(final_text.strip()) < min_chars // 2:
        if enable_local_fallback:
            if verbose:
                print("  [Guard] 最终文本仍偏短，启用本地兜底。")
            final_text = local_fallback_paragraph(meta, ref_entries)
            status = "fallback"
        else:
            return {"cve": cve_id, "status": "failed", "reason": "final_too_short"}
    else:
        status = "success"

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{meta_path.stem}_enhanced_report.txt"
    out_path.write_text(final_text, encoding="utf-8")

    return {
        "cve": cve_id,
        "status": status,
        "output": str(out_path),
        "chars": len(final_text),
        "model": used_model,
    }

def main():
    ap = argparse.ArgumentParser(description="CVE 报告生成（综合向量要点 + 反抄袭 + 多模型回退 + 防空写）")
    ap.add_argument("--meta_dir", required=True, help="元数据目录（含 CVE-*.json）")
    ap.add_argument("--ref_dir", required=True, help="ref 目录（CVE-*.json，每个是 list[ref]）")
    ap.add_argument("--output", required=True, help="输出报告目录")
    ap.add_argument("--model", default="gpt-4o", help="首选模型；其余会做自动回退")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--temp", type=float, default=0.3)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--no_skip_existing", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--min_chars", type=int, default=800, help="最小可接受字符数（长度闸门）")
    ap.add_argument("--plagiarism_threshold", type=float, default=PLAGIARISM_THRESHOLD)
    ap.add_argument("--enable_local_fallback", action="store_true", help="启用本地兜底以避免空文件")
    ap.add_argument("--max_meta_chars", type=int, default=5000, help="注入的 meta JSON 最大字符数")
    ap.add_argument("--max_notes_chars", type=int, default=6000, help="注入的 vector notes JSON 最大字符数")
    args = ap.parse_args()

    meta_dir = Path(args.meta_dir)
    ref_dir = Path(args.ref_dir)
    out_dir = Path(args.output)

    if not meta_dir.exists():
        print(f"❌ meta_dir 不存在: {meta_dir}")
        return
    if not ref_dir.exists():
        print(f"❌ ref_dir 不存在: {ref_dir}")
        return

    meta_files = sorted([p for p in meta_dir.glob("CVE-*.json")])
    if args.limit:
        meta_files = meta_files[:args.limit]

    # 构造模型链
    model_chain = [args.model] + [m for m in DEFAULT_MODEL_CHAIN if m != args.model]

    print("=" * 60)
    print("📝 CVE 报告生成（综合向量要点 + 反抄袭 + 多模型回退 + 防空写）")
    print("=" * 60)
    print(f"元数据目录: {meta_dir}")
    print(f"引用目录  : {ref_dir}")
    print(f"输出目录  : {out_dir}")
    print(f"首选模型  : {args.model}")
    print(f"超时      : {args.timeout}")
    print(f"温度      : {args.temp}")
    print(f"最小长度  : {args.min_chars}")
    print(f"跳过已存在: {'否(强制重算)' if args.no_skip_existing else '是'}")
    print(f"数量限制  : {args.limit or '无'}")
    print("=" * 60)
    print(f"发现元数据: {len(meta_files)} 个文件")

    total = len(meta_files)
    ok = fail = skip = fb = 0
    results = []

    for idx, meta_path in enumerate(meta_files, 1):
        cve_id = meta_path.stem
        out_path = out_dir / f"{cve_id}_enhanced_report.txt"
        if (not args.no_skip_existing) and out_path.exists() and out_path.stat().st_size >= args.min_chars//2:
            print(f"[{idx}/{total}] 跳过 {cve_id}（已存在且长度合格）")
            skip += 1
            continue

        ref_path = ref_dir / f"{cve_id}.json"
        print(f"[{idx}/{total}] 处理 {cve_id} ...")

        try:
            stat = process_one(
                meta_path=meta_path,
                ref_path=ref_path,
                out_dir=out_dir,
                model_chain=model_chain,
                timeout=args.timeout,
                temp=args.temp,
                min_chars=args.min_chars,
                plagiarism_threshold=args.plagiarism_threshold,
                verbose=args.verbose,
                enable_local_fallback=args.enable_local_fallback,
                max_meta_chars=args.max_meta_chars,
                max_notes_chars=args.max_notes_chars,
            )
            results.append(stat)
            if stat["status"] == "success":
                ok += 1
                print(f"  ✓ 成功：{cve_id} -> {stat['output']} ({stat['chars']} chars) via {stat.get('model','N/A')}")
            elif stat["status"] == "fallback":
                fb += 1
                print(f"  ✓ 兜底：{cve_id} -> {stat['output']} ({stat['chars']} chars) [local]")
            else:
                fail += 1
                print(f"  ✗ 失败：{cve_id} - {stat.get('reason')}")

        except KeyboardInterrupt:
            print("\n用户中断。")
            break
        except Exception as e:
            fail += 1
            print(f"  ✗ 异常：{cve_id} - {e}")

        # 温和限速
        if idx % 3 == 0:
            time.sleep(2)

    print("\n" + "=" * 60)
    print("📊 汇总")
    print("=" * 60)
    print(f"总数: {total}  | 成功: {ok}  | 兜底: {fb}  | 失败: {fail}  | 跳过: {skip}")
    succ_rate = (ok + fb) / total * 100 if total else 0
    print(f"成功率(含兜底): {succ_rate:.1f}%")
    stats_path = out_dir / "generation_stats.json"
    with stats_path.open("w", encoding="utf-8") as f:
        json.dump({"total": total, "success": ok, "fallback": fb, "failed": fail, "skipped": skip, "results": results}, f, ensure_ascii=False, indent=2)
    print(f"统计写出: {stats_path}")

if __name__ == "__main__":
    main()
