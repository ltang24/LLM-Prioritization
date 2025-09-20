#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RQ3-Exp2 (LLM 版)：
- 比较不同历史窗口（0.5/1/2/... 年）对 EPSS 预测的影响
- 协议：用 <= window 年的历史点预测“最后一个点”的数值
- 输出：逐样本明细、(Trend, Model, Window) 聚合表、折线图
"""

import os
import re
import json
import time
import random
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from tqdm import tqdm
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
import matplotlib.pyplot as plt

# ========= 配置 =========
USE_LLM = True              # 需要 LLM 预测
MAX_RETRIES = 3
WINDOW_YEARS = [0.5, 1.0, 2.0]   # 不同窗口（年）；可加 0.25/3/… 自行扩展
SAMPLE_PER_TREND = None     # None=全量，调小可快速验证

# Ground truth（保持与你的一致）
GT_MONO_DEC = "/home/xiaoqun/RQ3_Experimants/epss_classified/selected_epss_history_monotonic_decrease.json"
GT_MONO_INC = "/home/xiaoqun/RQ3_Experimants/epss_classified/selected_epss_history_monotonic_increase.json"
GT_STABLE   = "/home/xiaoqun/RQ3_Experimants/epss_classified/selected_epss_history_stable.json"
GT_SUDDEN   = "/home/xiaoqun/RQ3_Experimants/epss_classified/selected_epss_history_sudden_change.json"

REPORT_DIR = "/home/xiaoqun/RQ3_Experimants/enhanced_reports"
OUT_DIR    = "/home/xiaoqun/RQ3_Experimants/results_rq3_exp2_windows"

# 模型池
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


# ---------- 工具函数（与 Exp1 保持一致/兼容） ----------
def ensure_dir(p: str | Path):
    Path(p).mkdir(parents=True, exist_ok=True)

def parse_date(d: str) -> datetime:
    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(d, fmt)
        except Exception:
            pass
    return datetime.min

def get_score(rec: dict) -> Optional[float]:
    for k in ("new_score", "score", "epss", "value", "probability"):
        if k in rec:
            v = rec[k]
            if isinstance(v, (int, float)):
                return float(v)
            if isinstance(v, str):
                try:
                    vv = v.strip().rstrip('%')
                    return float(vv) / (100.0 if v.strip().endswith('%') else 1.0)
                except Exception:
                    pass
    return None

def sort_history(hist: List[dict]) -> List[dict]:
    return sorted(hist, key=lambda x: parse_date(x.get("date", "1900-01-01")))

def build_task(history_all: List[dict], window_days: int) -> Optional[dict]:
    """以最后一个点为 target；历史为之前 <= window_days 的点（至少 2 个历史）"""
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
        d = parse_date(r.get("date", "1900-01-01"))
        if (t_date - d).days <= window_days and get_score(r) is not None:
            hist.append(r)

    if len(hist) < 2:
        # 退化为：如果 window 里点太少，用全部先前点
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

    return {"Monotonic": monotonic, "Stable": stable, "Sudden_Change": sudden}

def read_report(cve_id: str) -> Optional[str]:
    fp = Path(REPORT_DIR) / f"{cve_id}_enhanced_report.txt"
    if fp.exists():
        try:
            t = fp.read_text(encoding="utf-8")
            return t[:2000] + ("\n[truncated...]" if len(t) > 2000 else "")
        except Exception:
            return None
    return None

def format_history_table(hist: List[dict]) -> str:
    lines = ["Row | Date       | EPSS | %  | Δ", "-" * 42]
    for i, r in enumerate(hist, 1):
        score = get_score(r) or 0.0
        pct = f"{score*100:.2f}%"
        delta = r.get("delta", 0.0)
        delta_s = f"{delta:+.4f}" if isinstance(delta, (int, float)) else str(delta)
        d = r.get("date", "N/A")
        lines.append(f"{i:3d} | {d} | {score:0.6f} | {pct:>6} | {delta_s}")
    return "\n".join(lines)

def make_prompt(cve_id: str, hist: List[dict], threat: Optional[str]) -> str:
    vals = [get_score(r) or 0.0 for r in hist]
    mean, std = np.mean(vals), np.std(vals)
    rng = (np.min(vals), np.max(vals))
    slope = (vals[-1] - vals[0]) / max(1, len(vals))
    trend = "Increasing" if slope > 0 else ("Decreasing" if slope < 0 else "Stable")
    tbl = format_history_table(hist)
    prompt = f"""You are a cybersecurity expert specialized in EPSS forecasting.

Task: Predict the NEXT EPSS score for {cve_id} (a number in [0.0, 1.0], no percent).

Historical window (chronological):
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
    pats = [
        r'^[\s]*(\d+\.?\d*)[\s]*$',
        r'(\d+\.\d+)',
        r'prediction[:\s]+(\d+\.?\d*)',
        r'score[:\s]+(\d+\.?\d*)',
    ]
    for p in pats:
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
            txt = resp['choices'][0]['message']['content'] if isinstance(resp, dict) and 'choices' in resp else str(resp)
            val = extract_float(txt)
            if val is not None:
                return val
        except Exception:
            time.sleep(2.0)
    return None
# ----------------------------------------------------------


def run_experiment_exp2():
    ensure_dir(OUT_DIR)
    inputs_dir = Path(OUT_DIR) / "llm_inputs"
    preds_dir  = Path(OUT_DIR) / "predictions"
    ensure_dir(inputs_dir); ensure_dir(preds_dir)

    classes = load_gt_to_three_classes()
    print("Loaded classes:", {k: len(v) for k, v in classes.items()})

    all_rows = []  # 每个样本的记录（含 window）

    for trend_name, cve_map in classes.items():
        cve_ids = list(cve_map.keys())
        if SAMPLE_PER_TREND and SAMPLE_PER_TREND < len(cve_ids):
            cve_ids = random.sample(cve_ids, SAMPLE_PER_TREND)

        print(f"\n==== {trend_name} ({len(cve_ids)} CVEs) ====")

        for model_name, model_obj in MODELS.items():
            for wy in WINDOW_YEARS:
                window_days = int(round(wy * 365))
                desc = f"{trend_name}-{model_name}-{wy}y"
                print(f"\nModel: {model_name} | Window: {wy}y ({window_days}d)")

                for cve_id in tqdm(cve_ids, desc=desc):
                    hist_all = cve_map[cve_id]
                    task = build_task(hist_all, window_days)
                    if not task:
                        continue

                    hist = task["history"]
                    target = task["target"]
                    target_score = task["target_score"]
                    target_date = task["target_date"]

                    # LLM 输入
                    threat = read_report(cve_id)
                    prompt = make_prompt(cve_id, hist, threat)

                    sample_key = f"{trend_name}__{model_name}__{wy}y__{cve_id}"
                    inputs_path = inputs_dir / f"{sample_key}.json"
                    with open(inputs_path, "w", encoding="utf-8") as f:
                        json.dump({
                            "trend": trend_name,
                            "model": model_name,
                            "window_years": wy,
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
                        "WindowYears": wy,
                        "WindowDays": window_days,
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
                    all_rows.append(row)

                    # 单样本预测也单独存
                    with open(preds_dir / f"{sample_key}.json", "w", encoding="utf-8") as f:
                        json.dump({"prediction": row}, f, indent=2, ensure_ascii=False)

    if not all_rows:
        print("\n[WARN] 没有有效样本。")
        return

    df = pd.DataFrame(all_rows)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 明细
    detail_csv = Path(OUT_DIR) / f"rq3_exp2_windows_detail_{ts}.csv"
    df.to_csv(detail_csv, index=False)
    print(f"[Saved] detail -> {detail_csv}")

    # 聚合 (Trend, Model, WindowYears)
    agg_rows = []
    for (trend, model, wy), g in df.groupby(["Trend", "Model", "WindowYears"]):
        preds = g["Pred"].values
        actuals = g["Actual"].values
        if len(g) == 0: 
            continue
        rmse = float(np.sqrt(mean_squared_error(actuals, preds)))
        mae  = float(mean_absolute_error(actuals, preds))
        mape = float(np.mean(np.where(actuals > 0, np.abs(preds - actuals) / actuals, 0)) * 100)
        r2   = float(r2_score(actuals, preds)) if len(g) > 1 else 0.0
        corr = float(np.corrcoef(preds, actuals)[0, 1]) if len(g) > 1 else 0.0
        diracc = float(g["DirCorrect"].mean()) * 100.0
        agg_rows.append({
            "Trend": trend, "Model": model, "WindowYears": wy,
            "Samples": int(len(g)), "RMSE": rmse, "MAE": mae,
            "MAPE(%)": mape, "R2": r2, "Corr": corr, "DirAcc(%)": diracc
        })
    summary = pd.DataFrame(agg_rows).sort_values(["Trend", "Model", "WindowYears"])
    summary_csv = Path(OUT_DIR) / f"rq3_exp2_windows_summary_{ts}.csv"
    summary.to_csv(summary_csv, index=False)
    print(f"[Saved] summary -> {summary_csv}")

    # ========== 画折线图 ==========
    # 统一风格（白底、黑字、Times New Roman）
    plt.rcParams.update({
        "figure.dpi": 120, "savefig.dpi": 200,
        "font.family": "Times New Roman",
        "text.color": "black", "axes.edgecolor": "black",
        "axes.labelcolor": "black", "xtick.color": "black",
        "ytick.color": "black", "axes.facecolor": "white",
        "figure.facecolor": "white",
        "legend.edgecolor": "black",
    })

    def plot_metric(trend: str, metric: str, ylabel: str, fname: str):
        sub = summary[summary["Trend"] == trend]
        if sub.empty:
            return
        # 横轴：WindowYears，曲线：Model
        models = sorted(sub["Model"].unique())
        xs = sorted(sub["WindowYears"].unique())
        fig, ax = plt.subplots(figsize=(9, 5.2))
        for m in models:
            y = []
            for x in xs:
                g = sub[(sub["Model"] == m) & (sub["WindowYears"] == x)]
                y.append(float(g[metric].values[0]) if not g.empty else np.nan)
            ax.plot(xs, y, marker='o', linewidth=2, label=m)
        ax.set_xlabel("History window (years)")
        ax.set_ylabel(ylabel)
        ax.set_title(f"{trend} — {metric} vs. window size", pad=6)
        ax.grid(True, linestyle='--', alpha=0.35)
        ax.legend(ncol=3, frameon=True, framealpha=0.95, fontsize=9)
        fig.tight_layout()
        outp = Path(OUT_DIR) / fname
        fig.savefig(outp, bbox_inches='tight')
        plt.close(fig)
        print(f"[Saved] {outp}")

    for tr in ["Monotonic", "Stable", "Sudden_Change"]:
        plot_metric(tr, "RMSE", "RMSE", f"exp2_{tr}_rmse.png")
        plot_metric(tr, "MAE",  "MAE",  f"exp2_{tr}_mae.png")
        plot_metric(tr, "DirAcc(%)", "Direction accuracy (%)", f"exp2_{tr}_diracc.png")

    # 控制台预览
    print("\n===== Summary (by Trend, Model, WindowYears) =====")
    print(summary.to_string(index=False))


if __name__ == "__main__":
    random.seed(42); np.random.seed(42)
    run_experiment_exp2()
