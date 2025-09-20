#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RQ3-Exp1 (LLM 版)：
- 三大类趋势：Monotonic(含increase/decrease)、Stable、Sudden_Change
- 用过去 <= 0.5 年（180天）的历史，预测“下一个最近点”（我们取最后一个点作为 target，历史为之前点）
- 把 history + threat report 喂给 LLM，拿预测，和真值对比
- 输出：逐样本明细（含 LLM 输入历史与输出）、按类别&模型汇总表、可选图
"""

import os
import json
import time
import random
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from tqdm import tqdm
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score

# ====== 配置区域 ======
USE_LLM = True             # 需要 LLM 预测
MAX_RETRIES = 3            # LLM 调用重试
WINDOW_DAYS = 180          # 历史窗口：<= 0.5 年（180天）
SAMPLE_PER_TREND = None    # None 表示全量；调小便于快速验证

# Ground truth（你给的四个文件）
GT_MONO_DEC = "/home/xiaoqun/RQ3_Experimants/epss_classified/selected_epss_history_monotonic_decrease.json"
GT_MONO_INC = "/home/xiaoqun/RQ3_Experimants/epss_classified/selected_epss_history_monotonic_increase.json"
GT_STABLE   = "/home/xiaoqun/RQ3_Experimants/epss_classified/selected_epss_history_stable.json"
GT_SUDDEN   = "/home/xiaoqun/RQ3_Experimants/epss_classified/selected_epss_history_sudden_change.json"

REPORT_DIR = "/home/xiaoqun/RQ3_Experimants/enhanced_reports"
OUT_DIR    = "/home/xiaoqun/RQ3_Experimants/results_rq3_exp1_llm"

# 模型池（按需增减）
try:
    import g4f
    MODELS = {
        "gpt-4o": getattr(g4f.models, "gpt_4o", None),
        "gpt-4": getattr(g4f.models, "gpt_4", None),
        "gpt-4o-mini": getattr(g4f.models, "gpt_4o_mini", None),
        "gemini-1.5-pro": getattr(g4f.models, "gemini_1_5_pro", None),
        "gemini-1.5-flash": getattr(g4f.models, "gemini_1_5_flash", None),
        "command-r": getattr(g4f.models, "command_r", None),
        "blackboxai": getattr(g4f.models, "blackboxai", None),
    }
except Exception:
    MODELS = {"baseline": None}
# ======================


def ensure_dir(p: str | Path):
    Path(p).mkdir(parents=True, exist_ok=True)


def parse_date(d: str) -> datetime:
    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(d, fmt)
        except Exception:
            pass
    # 宽松失败：尽量返回很小或很大避免影响
    return datetime.min


def get_score(rec: dict) -> Optional[float]:
    """容错读取分数字段：new_score/score/epss/value/probability/百分数字符串"""
    for k in ("new_score", "score", "epss", "value", "probability"):
        if k in rec:
            v = rec[k]
            if isinstance(v, (int, float)):
                return float(v)
            if isinstance(v, str):
                try:
                    # 处理可能的 '27.59%' 之类
                    vv = v.strip().rstrip('%')
                    return float(vv) / (100.0 if v.strip().endswith('%') else 1.0)
                except Exception:
                    pass
    return None


def sort_history(hist: List[dict]) -> List[dict]:
    return sorted(hist, key=lambda x: parse_date(x["date"]) if "date" in x else datetime.min)


def build_task(history_all: List[dict], window_days: int = 180) -> Optional[dict]:
    """以最后一个点为 target，历史是之前 <= window_days 的点（最少两个历史，否则返回 None）"""
    if not history_all:
        return None

    hist_sorted = sort_history(history_all)
    if len(hist_sorted) < 2:
        return None

    target = hist_sorted[-1]
    t_score = get_score(target)
    if t_score is None:
        return None

    t_date = parse_date(target["date"])
    hist = []
    for r in hist_sorted[:-1]:
        d = parse_date(r["date"]) if "date" in r else datetime.min
        if (t_date - d).days <= window_days:
            if get_score(r) is not None:
                hist.append(r)

    if len(hist) < 2:
        # 退化为用全部先前点
        hist = [r for r in hist_sorted[:-1] if get_score(r) is not None]
        if len(hist) < 2:
            return None

    return {
        "history": sort_history(hist),
        "target": target,
        "target_score": t_score,
        "target_date": target["date"]
    }


def load_gt_to_three_classes() -> Dict[str, Dict[str, List[dict]]]:
    """加载四个 GT 文件并合并为三大类：Monotonic / Stable / Sudden_Change"""
    def _load_json(p: str) -> Dict[str, List[dict]]:
        if not os.path.exists(p):
            print(f"[WARN] not found: {p}")
            return {}
        with open(p, "r") as f:
            return json.load(f)

    mono_dec = _load_json(GT_MONO_DEC)
    mono_inc = _load_json(GT_MONO_INC)
    stable   = _load_json(GT_STABLE)
    sudden   = _load_json(GT_SUDDEN)

    monotonic = {}
    monotonic.update(mono_dec)
    monotonic.update(mono_inc)

    return {
        "Monotonic": monotonic,
        "Stable": stable,
        "Sudden_Change": sudden
    }


def read_report(cve_id: str) -> Optional[str]:
    fp = Path(REPORT_DIR) / f"{cve_id}_enhanced_report.txt"
    if fp.exists():
        try:
            txt = fp.read_text(encoding="utf-8")
            return txt[:2000] + ("\n[truncated...]" if len(txt) > 2000 else "")
        except Exception:
            return None
    return None


def format_history_table(hist: List[dict]) -> str:
    lines = ["Row | Date       | EPSS | %  | Δ"]
    lines.append("-" * 42)
    for i, r in enumerate(hist, 1):
        score = get_score(r) or 0.0
        pct = f"{score*100:.2f}%"
        delta = r.get("delta", 0.0)
        if isinstance(delta, (int, float)):
            delta_s = f"{delta:+.4f}"
        else:
            delta_s = str(delta)
        d = r.get("date", "N/A")
        lines.append(f"{i:3d} | {d} | {score:0.6f} | {pct:>6} | {delta_s}")
    return "\n".join(lines)


def make_prompt(cve_id: str, hist: List[dict], threat: Optional[str]) -> str:
    stats_scores = [get_score(r) or 0.0 for r in hist]
    mean = np.mean(stats_scores)
    std = np.std(stats_scores)
    rng = (np.min(stats_scores), np.max(stats_scores))
    trend_slope = (stats_scores[-1] - stats_scores[0]) / max(1, len(stats_scores))
    trend = "Increasing" if trend_slope > 0 else ("Decreasing" if trend_slope < 0 else "Stable")

    tbl = format_history_table(hist)
    prompt = f"""You are a cybersecurity expert specialized in EPSS forecasting.

Task: Predict the NEXT EPSS score for {cve_id} (a number in [0.0, 1.0], no percent).

Historical window (chronological, <=6 months):
{tbl}

Stats:
- Points: {len(hist)}
- Mean: {mean:.6f} ({mean*100:.2f}%)
- Std: {std:.6f}
- Range: [{rng[0]:.6f}, {rng[1]:.6f}]
- Trend: {trend}

Instruction:
Return ONLY one decimal number between 0.0 and 1.0 (no additional text).
"""
    if threat and len(threat) > 100:
        prompt += f"\nThreat intel (truncated):\n{threat[:800]}...\n"
    return prompt.strip()


def extract_float(resp_text: str) -> Optional[float]:
    patterns = [
        r'^[\s]*(\d+\.?\d*)[\s]*$',
        r'(\d+\.\d+)',
        r'prediction[:\s]+(\d+\.?\d*)',
        r'score[:\s]+(\d+\.?\d*)',
    ]
    for p in patterns:
        m = re.search(p, resp_text, re.IGNORECASE | re.MULTILINE)
        if not m:
            continue
        try:
            v = float(m.group(1))
            if ('%' in resp_text) and v > 1:
                v = v / 100.0
            if 0.0 <= v <= 1.0:
                return round(v, 6)
        except Exception:
            pass
    return None


def baseline_predict(hist: List[dict]) -> float:
    vals = [get_score(r) or 0.0 for r in hist]
    if len(vals) >= 3:
        pred = vals[-1] + (vals[-1] - vals[-3])
    elif len(vals) == 2:
        pred = vals[-1] + (vals[-1] - vals[-2])
    else:
        pred = vals[-1] if vals else 0.0
    return float(np.clip(pred, 0.0, 1.0))


def llm_predict(model_obj, prompt: str) -> Optional[float]:
    for _ in range(MAX_RETRIES):
        try:
            time.sleep(random.uniform(1.0, 2.0))
            resp = g4f.ChatCompletion.create(
                model=model_obj,
                messages=[{"role": "user", "content": prompt}],
                stream=False
            )
            if isinstance(resp, dict) and 'choices' in resp and resp['choices']:
                txt = resp['choices'][0].get('message', {}).get('content', '')
            else:
                txt = str(resp)
            val = extract_float(txt)
            if val is not None:
                return val
        except Exception:
            time.sleep(2.0)
            continue
    return None


def run_experiment():
    ensure_dir(OUT_DIR)
    inputs_dir = Path(OUT_DIR) / "llm_inputs"
    preds_dir  = Path(OUT_DIR) / "predictions"
    ensure_dir(inputs_dir)
    ensure_dir(preds_dir)

    classes = load_gt_to_three_classes()
    print("Loaded classes:", {k: len(v) for k, v in classes.items()})

    all_rows = []  # 明细表
    all_hist_dump = {}  # 每个样本的喂入历史（按文件分）

    for trend_name, cve_map in classes.items():
        cve_ids = list(cve_map.keys())
        if SAMPLE_PER_TREND and SAMPLE_PER_TREND < len(cve_ids):
            cve_ids = random.sample(cve_ids, SAMPLE_PER_TREND)

        print(f"\n==== {trend_name} ({len(cve_ids)} CVEs) ====")

        for model_name, model_obj in MODELS.items():
            print(f"\nModel: {model_name}")
            rows_this = []

            for cve_id in tqdm(cve_ids, desc=f"{trend_name}-{model_name}"):
                hist_all = cve_map[cve_id]
                task = build_task(hist_all, WINDOW_DAYS)
                if not task:
                    continue

                hist = task["history"]
                target = task["target"]
                target_score = task["target_score"]
                target_date = task["target_date"]

                threat = read_report(cve_id)
                prompt = make_prompt(cve_id, hist, threat)

                # 保存输入（history + prompt）便于复现实验
                sample_key = f"{trend_name}__{model_name}__{cve_id}"
                inputs_path = inputs_dir / f"{sample_key}.json"
                with open(inputs_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "trend": trend_name,
                        "model": model_name,
                        "cve_id": cve_id,
                        "target_date": target_date,
                        "target_record": target,
                        "history_used": hist,
                        "prompt": prompt
                    }, f, indent=2, ensure_ascii=False)

                if USE_LLM and model_obj is not None:
                    pred = llm_predict(model_obj, prompt)
                    used_llm = pred is not None
                    if pred is None:
                        pred = baseline_predict(hist)
                else:
                    pred = baseline_predict(hist)
                    used_llm = False

                last_hist = get_score(hist[-1]) or 0.0
                row = {
                    "Trend": trend_name,
                    "Model": model_name,
                    "CVE": cve_id,
                    "TargetDate": target_date,
                    "Pred": float(pred),
                    "Actual": float(target_score),
                    "AbsError": float(abs(pred - target_score)),
                    "SqError": float((pred - target_score) ** 2),
                    "PctError": float(abs(pred - target_score) / target_score * 100) if target_score > 0 else 0.0,
                    "PredDir": 1 if pred > last_hist else -1,
                    "ActualDir": 1 if target_score > last_hist else -1,
                    "DirCorrect": int((pred > last_hist) == (target_score > last_hist)),
                    "HistoryPoints": len(hist),
                    "LLM_Used": int(used_llm),
                    "InputsPath": str(inputs_path)
                }
                rows_this.append(row)

                # 单样本预测也另存一份
                pred_path = preds_dir / f"{sample_key}.json"
                with open(pred_path, "w", encoding="utf-8") as f:
                    json.dump({"prediction": row}, f, indent=2, ensure_ascii=False)

            all_rows.extend(rows_this)

    # 汇总与导出
    if not all_rows:
        print("\n[WARN] 没有有效样本（可能历史点不足或数据格式不一致）。")
        return

    df = pd.DataFrame(all_rows)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 逐样本明细
    detail_csv = Path(OUT_DIR) / f"rq3_exp1_llm_detail_{ts}.csv"
    df.to_csv(detail_csv, index=False)
    print(f"[Saved] detail -> {detail_csv}")

    # 按类别&模型汇总
    agg = []
    for (trend, model), g in df.groupby(["Trend", "Model"]):
        preds = g["Pred"].values
        actuals = g["Actual"].values
        if len(g) == 0:
            continue
        rmse = float(np.sqrt(mean_squared_error(actuals, preds)))
        mae = float(mean_absolute_error(actuals, preds))
        mape = float(np.mean(np.where(actuals > 0, np.abs(preds - actuals) / actuals, 0)) * 100)
        r2 = float(r2_score(actuals, preds)) if len(g) > 1 else 0.0
        corr = float(np.corrcoef(preds, actuals)[0, 1]) if len(g) > 1 else 0.0
        dir_acc = float(g["DirCorrect"].mean())
        n = int(len(g))
        llm_rate = float(g["LLM_Used"].mean())
        agg.append({
            "Trend": trend,
            "Model": model,
            "Samples": n,
            "RMSE": rmse,
            "MAE": mae,
            "MAPE(%)": mape,
            "R2": r2,
            "Corr": corr,
            "DirAcc(%)": dir_acc * 100.0,
            "LLM_Usage(%)": llm_rate * 100.0
        })
    summary_df = pd.DataFrame(agg).sort_values(["Trend", "Model"])
    summary_csv = Path(OUT_DIR) / f"rq3_exp1_llm_summary_{ts}.csv"
    summary_df.to_csv(summary_csv, index=False)
    print(f"[Saved] summary -> {summary_csv}")

    # 控制台打印一份
    print("\n===== Summary (by Trend & Model) =====")
    print(summary_df.to_string(index=False))

    # 也存一份 JSON 结果
    results_json = Path(OUT_DIR) / f"rq3_exp1_llm_results_{ts}.json"
    out_obj = {
        "detail_file": str(detail_csv),
        "summary_file": str(summary_csv),
        "rows": all_rows
    }
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=2, ensure_ascii=False)
    print(f"[Saved] json -> {results_json}")


if __name__ == "__main__":
    random.seed(42)
    np.random.seed(42)
    run_experiment()
