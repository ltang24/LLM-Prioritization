#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多模型CVSS Metrics预测器（修复版，固定到 2024 年目录）
- 报告文件位于: /home/xiaoqun/RQ2_Experiments/enhanced_threat_reports/2024/<bucket>/CVE-2024-xxxx_enhanced_report.txt
- 只有当缓存结果“通过校验”才会跳过预测
- 健壮的 g4f 响应与 Metrics 解析
- 更详细的日志与评估
"""

import os
import json
import numpy as np
import g4f
import re
from time import sleep
import random
from tqdm import tqdm
from collections import Counter
from datetime import datetime
import glob
import matplotlib
matplotlib.use("Agg")  # 服务器无显示环境时防崩
import matplotlib.pyplot as plt
import pandas as pd

# ======================== 配置 ========================
# 报告根目录固定在 2024 年（你的数据都在这里）
REPORT_DIR_2024 = "/home/xiaoqun/RQ2_Experiments/enhanced_threat_reports/2024"
GT_PATH = "/home/xiaoqun/RQ2_Experiments/GT_Data/cvss_2024_9xxx.json"
OUTPUT_DIR = "/home/xiaoqun/RQ2_Experiments/multi_model_results2"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 定义要测试的模型（按你的 g4f 安装适配）
MODELS_TO_TEST = {
    'gemini-1.5-flash': g4f.models.gemini_1_5_flash,
    'command-r': g4f.models.command_r,
    'blackboxai': g4f.models.blackboxai,
}

# Ground Truth来源优先级（越小优先级越高）
SOURCE_PRIORITY = {
    'NIST': 1,
    'Wordfence': 2,
    'GitHub': 3,
    'VulDB': 4,
    'TWCERT/CC': 5,
    'huntr.dev': 6,
    'Red Hat, Inc.': 7,
    'Hitachi Energy': 8,
    'Forescout': 9,
    'Fortra': 10,
    'Indian Computer Emergency Response Team (CERT-In)': 11,
    'Progress Software Corporation': 12,
    # 兜底
    'Unknown': 999
}

# 合法取值集合
VALID = {
    'AV': set('NALP'),
    'AC': set('LH'),
    'PR': set('NLH'),
    'UI': set('NR'),
    'S' : set('UC'),
    'C' : set('HLN'),
    'I' : set('HLN'),
    'A' : set('HLN'),
}
METRIC_KEYS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']


def is_valid_metrics(x: dict) -> bool:
    """校验预测结果是否为包含8个键、且取值合法的字典"""
    if not isinstance(x, dict):
        return False
    for k in METRIC_KEYS:
        v = x.get(k, None)
        if not isinstance(v, str):
            return False
        u = v.strip().upper()
        if k not in VALID or u not in VALID[k]:
            return False
    return True


def find_report_path_2024(cve_id: str) -> str | None:
    """
    在 2024 年目录下寻找报告文件：
    - 固定根目录: REPORT_DIR_2024
    - 计算 <bucket> = floor(num/1000) + 'xxx'
    - 路径: <root>/<bucket>/<CVE>_enhanced_report.txt
    - 若上述路径不存在，则在 2024 下递归搜索兜底
    """
    filename = f"{cve_id}_enhanced_report.txt"
    try:
        parts = cve_id.split("-")
        year = parts[1]
        num = int(parts[2])
    except Exception:
        year = "2024"
        num = 0

    # 即便 CVE 年份不是 2024，本函数也固定在 2024 目录找（符合你的数据现状）
    bucket = f"{num // 1000}xxx"
    p = os.path.join(REPORT_DIR_2024, bucket, filename)
    if os.path.exists(p):
        return p

    # 兜底：只在 2024 目录下递归搜索
    hits = glob.glob(os.path.join(REPORT_DIR_2024, "**", filename), recursive=True)
    if hits:
        return sorted(hits, key=len)[0]
    return None


# ======================== CVSS公式实现 ========================
def cvss3_base_score(metrics):
    """根据8个CVSS metrics计算base score"""
    AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    AC = {'L': 0.77, 'H': 0.44}
    PR = {'N': {'U': 0.85, 'C': 0.85}, 'L': {'U': 0.62, 'C': 0.68}, 'H': {'U': 0.27, 'C': 0.5}}
    UI = {'N': 0.85, 'R': 0.62}
    C = {'H': 0.56, 'L': 0.22, 'N': 0.0}

    try:
        av = AV[metrics['AV']]
        ac = AC[metrics['AC']]
        pr = PR[metrics['PR']][metrics['S']]
        ui = UI[metrics['UI']]
        c = C[metrics['C']]
        i = C[metrics['I']]
        a = C[metrics['A']]
        s = metrics['S']

        impact = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact_score = 6.42 * impact if s == 'U' else 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15
        exploitab = 8.22 * av * ac * pr * ui

        if impact <= 0:
            base_score = 0
        else:
            tmp = impact_score + exploitab
            base_score = min(tmp if s == 'U' else 1.08 * tmp, 10)

        return round(base_score, 1)

    except Exception as e:
        print(f"[ERR] CVSS calc failed: {e} | metrics={metrics}")
        return None


# ======================== Ground Truth处理 ========================
class GroundTruthHandler:
    def __init__(self, gt_path):
        with open(gt_path, "r", encoding="utf-8") as f:
            self.gt_data = json.load(f)

    def get_best_ground_truth(self, cve_id):
        records = self.gt_data.get(cve_id, [])
        if not records:
            return None, None, None

        valid_records = []
        for record in records:
            if record.get("base_score") is not None and record.get("cvss_vector"):
                source = record.get("score_source", "Unknown")
                priority = SOURCE_PRIORITY.get(source, 999)
                valid_records.append((priority, record))

        if not valid_records:
            return None, None, None

        valid_records.sort(key=lambda x: x[0])
        best = valid_records[0][1]
        return (
            float(best["base_score"]),
            best["cvss_vector"],
            best.get("score_source", "Unknown")
        )

    def parse_cvss_vector(self, cvss_vector):
        if not cvss_vector:
            return None
        # v3.x
        pattern_v3 = r'CVSS:3\.[01]/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])'
        m = re.search(pattern_v3, cvss_vector)
        if m:
            return dict(zip(METRIC_KEYS, m.groups()))
        # 容错（不带 CVSS:3.x 前缀）
        pattern_soft_v3 = r'AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])'
        m2 = re.search(pattern_soft_v3, cvss_vector)
        if m2:
            return dict(zip(METRIC_KEYS, m2.groups()))
        # v2 映射（粗略）
        pattern_v2 = r'AV:([NAL])/AC:([LMH])/Au:([NSM])/C:([NPC])/I:([NPC])/A:([NPC])'
        m3 = re.search(pattern_v2, cvss_vector)
        if m3:
            av_v2, ac_v2, au_v2, c_v2, i_v2, a_v2 = m3.groups()
            av_map = {'N': 'N', 'A': 'A', 'L': 'L'}
            ac_map = {'L': 'L', 'M': 'H', 'H': 'H'}
            pr_map = {'N': 'N', 'S': 'L', 'M': 'H'}
            impact_map = {'N': 'N', 'P': 'L', 'C': 'H'}
            return {
                'AV': av_map.get(av_v2, 'N'),
                'AC': ac_map.get(ac_v2, 'L'),
                'PR': pr_map.get(au_v2, 'L'),
                'UI': 'N',
                'S' : 'U',
                'C' : impact_map.get(c_v2, 'L'),
                'I' : impact_map.get(i_v2, 'L'),
                'A' : impact_map.get(a_v2, 'L'),
            }
        return None


# ======================== 多模型预测器 ========================
class MultiModelCVSSPredictor:
    def __init__(self, models_dict):
        self.models = models_dict

    def predict_metrics_with_model(self, report, model_name, model, max_retries=3):
        prompt = self._create_prompt(report)
        last_err = None
        for attempt in range(1, max_retries + 1):
            try:
                resp = g4f.ChatCompletion.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    stream=False
                )
                text = self._extract_text(resp)
                metrics = self._parse_metrics_from_response(text)
                if is_valid_metrics(metrics):
                    return metrics
                else:
                    print(f"[WARN] {model_name} attempt {attempt}: parsed but invalid -> {metrics}")
            except Exception as e:
                last_err = e
                print(f"[WARN] {model_name} attempt {attempt} failed: {e}")
            sleep(random.uniform(1.5, 3.5))
        print(f"[FAIL] {model_name} exhausted retries. last_err={last_err}")
        return None

    def _extract_text(self, response):
        """把 g4f 的各种返回形态统一成纯文本"""
        if response is None:
            return ""
        if isinstance(response, str):
            return response
        # OpenAI 风格
        try:
            if isinstance(response, dict):
                if "choices" in response and response["choices"]:
                    ch = response["choices"][0]
                    if "message" in ch and "content" in ch["message"]:
                        return ch["message"]["content"] or ""
                    if "text" in ch:
                        return ch["text"] or ""
                # 其它字段兜底
                return json.dumps(response, ensure_ascii=False)
        except Exception:
            pass
        # 兜底
        try:
            return str(response)
        except Exception:
            return ""

    def _create_prompt(self, report):
        return f"""Analyze the following CVE threat report and determine the CVSS v3.1 Base Metrics.

Answer ONLY the metrics string in the exact format:
AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X

CVE Report (may be truncated):
{report[:6000]}
"""

    def _parse_metrics_from_response(self, text: str):
        if not text:
            return None

        # 1) 严格格式
        strict = r"AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])"
        m = re.search(strict, text)
        if m:
            d = dict(zip(METRIC_KEYS, [x.upper() for x in m.groups()]))
            return d

        # 2) 容错：允许空格/换行/中文冒号/多余字符
        soft = (
            r"AV[:：]?\s*([NALPnalp])[^A-Za-z0-9]*"
            r"AC[:：]?\s*([LHlh])[^A-Za-z0-9]*"
            r"PR[:：]?\s*([NLHnlh])[^A-Za-z0-9]*"
            r"UI[:：]?\s*([NRnr])[^A-Za-z0-9]*"
            r"S[:：]?\s*([UCuc])[^A-Za-z0-9]*"
            r"C[:：]?\s*([HLNhln])[^A-Za-z0-9]*"
            r"I[:：]?\s*([HLNhln])[^A-Za-z0-9]*"
            r"A[:：]?\s*([HLNhln])"
        )
        m2 = re.search(soft, text, re.IGNORECASE | re.DOTALL)
        if m2:
            d = dict(zip(METRIC_KEYS, [x.upper() for x in m2.groups()]))
            return d

        # 3) JSON 风格
        try:
            json_like = re.search(r"\{.*\}", text, re.DOTALL)
            if json_like:
                candidate = json.loads(json_like.group(0))
                out = {k: str(candidate.get(k, "")).strip().upper() for k in METRIC_KEYS}
                if is_valid_metrics(out):
                    return out
        except Exception:
            pass

        # 4) 直接是 "AV:N/AC:L/..." 的整行字符串
        just_line = re.search(r"(AV:[^ \n]+/AC:[^ \n]+/PR:[^ \n]+/UI:[^ \n]+/S:[^ \n]+/C:[^ \n]+/I:[^ \n]+/A:[^ \n]+)", text)
        if just_line:
            return self._parse_metrics_from_response(just_line.group(1))

        print(f"[WARN] parse failed on text head: {text[:200]!r}")
        return None


# ======================== 评估器 ========================
class ModelEvaluator:
    def __init__(self):
        self.metric_names = {
            'AV': 'Attack Vector',
            'AC': 'Attack Complexity',
            'PR': 'Privileges Required',
            'UI': 'User Interaction',
            'S' : 'Scope',
            'C' : 'Confidentiality',
            'I' : 'Integrity',
            'A' : 'Availability'
        }

    def evaluate_model_results(self, model_results, gt_handler):
        metrics_accuracy = {m: {'correct': 0, 'total': 0} for m in METRIC_KEYS}
        scores_pred, scores_gt = [], []
        n_pred_valid = 0

        for cve_id, pred in model_results.items():
            if not is_valid_metrics(pred):
                continue
            n_pred_valid += 1

            gt_score, gt_vector, _ = gt_handler.get_best_ground_truth(cve_id)
            if gt_score is None or gt_vector is None:
                continue
            gt_metrics = gt_handler.parse_cvss_vector(gt_vector)
            if not is_valid_metrics(gt_metrics):
                continue

            # metrics 准确率
            for k in METRIC_KEYS:
                metrics_accuracy[k]['total'] += 1
                if pred[k] == gt_metrics[k]:
                    metrics_accuracy[k]['correct'] += 1

            # 分数
            ps = cvss3_base_score(pred)
            if ps is not None:
                scores_pred.append(ps)
                scores_gt.append(gt_score)

        # 指标
        if scores_pred:
            rmse = float(np.sqrt(np.mean((np.array(scores_pred) - np.array(scores_gt)) ** 2)))
            mae = float(np.mean(np.abs(np.array(scores_pred) - np.array(scores_gt))))
            corr = float(np.corrcoef(scores_pred, scores_gt)[0, 1]) if len(scores_pred) > 1 else 0.0
        else:
            rmse = mae = corr = 0.0

        metric_acc = {}
        for k in METRIC_KEYS:
            t = metrics_accuracy[k]['total']
            metric_acc[k] = (metrics_accuracy[k]['correct'] / t * 100.0) if t > 0 else 0.0

        return {
            'metrics_accuracy': metric_acc,
            'rmse': rmse,
            'mae': mae,
            'correlation': corr,
            'n_samples': len(scores_pred),   # 用于 RMSE/MAE 的样本数
            'n_pred_valid': n_pred_valid     # 通过校验的预测条数
        }


# ======================== 可视化 ========================
def create_visualizations(all_results):
    models = list(all_results.keys())

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    x = np.arange(len(METRIC_KEYS))
    width = 0.15

    for i, model in enumerate(models):
        evald = all_results[model].get('evaluation', {})
        accs = [evald.get('metrics_accuracy', {}).get(m, 0.0) for m in METRIC_KEYS]
        bars = ax1.bar(x + i * width, accs, width, label=model)
        for b in bars:
            h = b.get_height()
            if h > 0:
                ax1.text(b.get_x() + b.get_width()/2., h + 1, f'{h:.0f}', ha='center', va='bottom', fontsize=8)

    ax1.set_xlabel('CVSS Metrics', fontweight='bold')
    ax1.set_ylabel('Accuracy (%)', fontweight='bold')
    ax1.set_title('CVSS Metrics Accuracy - Multi-Model', fontweight='bold')
    ax1.set_xticks(x + width * (len(models) - 1) / 2)
    ax1.set_xticklabels(METRIC_KEYS)
    ax1.legend(loc='upper left')
    ax1.grid(True, alpha=0.3, axis='y')
    ax1.set_ylim(0, 110)

    rmse_vals = [all_results[m]['evaluation']['rmse'] for m in models]
    b2 = ax2.bar(range(len(models)), rmse_vals)
    for bar, val in zip(b2, rmse_vals):
        ax2.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.05, f'{val:.3f}', ha='center', va='bottom', fontweight='bold')
    ax2.set_xlabel('Model', fontweight='bold')
    ax2.set_ylabel('RMSE', fontweight='bold')
    ax2.set_title('CVSS Score RMSE - Multi-Model', fontweight='bold')
    ax2.set_xticks(range(len(models)))
    ax2.set_xticklabels(models, rotation=45, ha='right')
    ax2.grid(True, alpha=0.3, axis='y')

    plt.tight_layout()
    plt.savefig(f'{OUTPUT_DIR}/multi_model_comparison.png', dpi=300, bbox_inches='tight')

    # 明细表
    rows = []
    for m in models:
        ev = all_results[m]['evaluation']
        row = {'Model': m}
        row.update({k: f"{ev['metrics_accuracy'].get(k, 0.0):.1f}%" for k in METRIC_KEYS})
        row['Avg Accuracy'] = f"{np.mean(list(ev['metrics_accuracy'].values())):.1f}%"
        row['RMSE'] = f"{ev['rmse']:.3f}"
        row['MAE'] = f"{ev['mae']:.3f}"
        row['Correlation'] = f"{ev['correlation']:.3f}"
        row['Samples'] = ev['n_samples']
        row['Valid Pred'] = ev.get('n_pred_valid', 0)
        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv(f'{OUTPUT_DIR}/multi_model_results.csv', index=False)
    print("\n" + "="*80)
    print("MULTI-MODEL COMPARISON RESULTS")
    print("="*80)
    print(df.to_string(index=False))
    return df


# ======================== 主程序 ========================
def main():
    random.seed(42)
    np.random.seed(42)

    print("="*80)
    print("MULTI-MODEL CVSS PREDICTION EXPERIMENT (Fixed; reports under 2024/*)")
    print("="*80)

    # 初始化
    gt_handler = GroundTruthHandler(GT_PATH)
    predictor = MultiModelCVSSPredictor(MODELS_TO_TEST)
    evaluator = ModelEvaluator()

    # 获取有效 CVE
    print("\nFiltering valid CVE IDs...")
    valid_cves = []
    source_stats = Counter()
    for cve_id in gt_handler.gt_data.keys():
        gt_score, gt_vector, gt_source = gt_handler.get_best_ground_truth(cve_id)
        if gt_score is not None and gt_vector is not None:
            valid_cves.append(cve_id)
            source_stats[gt_source] += 1

    print(f"Found {len(valid_cves)} valid CVE IDs")
    print("Ground Truth source distribution:")
    for s, c in source_stats.most_common():
        print(f"  {s}: {c}")

    # 可配置测试数量（None=全部）
    TEST_LIMIT = 100  # 或改为 None 全量
    if TEST_LIMIT is not None and len(valid_cves) > TEST_LIMIT:
        valid_cves = random.sample(valid_cves, TEST_LIMIT)
        print(f"\nLimited to {TEST_LIMIT} CVEs for testing")

    all_results = {}

    for model_name, model in MODELS_TO_TEST.items():
        print(f"\n{'='*60}")
        print(f"Testing Model: {model_name}")
        print(f"{'='*60}")

        result_file = f"{OUTPUT_DIR}/{model_name}_results.json"
        model_results = {}
        cached_valid = cached_invalid = 0

        # 读取缓存（只接收“通过校验”的缓存）
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r', encoding='utf-8') as f:
                    tmp = json.load(f)
                for k, v in tmp.items():
                    if is_valid_metrics(v):
                        model_results[k] = {m: v[m].upper() for m in METRIC_KEYS}
                        cached_valid += 1
                    else:
                        cached_invalid += 1
            except Exception as e:
                print(f"[WARN] Failed to load cache {result_file}: {e}")

        print(f"[CACHE] valid={cached_valid}, invalid_or_skipped={cached_invalid}")

        need_report_missing = 0
        skipped_by_cache = 0
        predicted_cnt = 0
        fail_cnt = 0

        progress_bar = tqdm(valid_cves, desc=f"Processing with {model_name}")
        for cve_id in progress_bar:
            # 缓存通过校验则跳过
            if cve_id in model_results and is_valid_metrics(model_results[cve_id]):
                skipped_by_cache += 1
                continue

            # 读取 2024 目录下的报告
            report_file = find_report_path_2024(cve_id)
            if report_file is None:
                need_report_missing += 1
                continue
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    report = f.read()
            except Exception as e:
                print(f"[WARN] Read report failed for {cve_id}: {e}")
                need_report_missing += 1
                continue

            if len(report) > 9000:
                report = report[:9000] + "\n[Report truncated due to length]"

            # 预测
            progress_bar.set_postfix({'CVE': cve_id})
            pred = predictor.predict_metrics_with_model(report, model_name, model)
            if is_valid_metrics(pred):
                model_results[cve_id] = {m: pred[m].upper() for m in METRIC_KEYS}
                predicted_cnt += 1
            else:
                model_results[cve_id] = None
                fail_cnt += 1

            # 定期保存
            if (predicted_cnt + fail_cnt) % 10 == 0:
                with open(result_file, 'w', encoding='utf-8') as f:
                    json.dump(model_results, f, indent=2, ensure_ascii=False)

            # 轻微延迟防限流
            sleep(random.uniform(1.2, 2.4))

        # 最终保存
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(model_results, f, indent=2, ensure_ascii=False)

        print(f"[STATS] {model_name} | cached_ok={skipped_by_cache}, predicted={predicted_cnt}, "
              f"report_missing={need_report_missing}, predict_fail={fail_cnt}")

        # 评估
        evaluation = evaluator.evaluate_model_results(model_results, gt_handler)
        all_results[model_name] = {
            'predictions': model_results,
            'evaluation': evaluation
        }

        avg_acc = float(np.mean(list(evaluation['metrics_accuracy'].values()))) if evaluation['metrics_accuracy'] else 0.0
        print(f"\n{model_name} Results:")
        print(f"  Valid predictions (passed schema check): {evaluation['n_pred_valid']}")
        print(f"  Samples used for RMSE/MAE: {evaluation['n_samples']}")
        print(f"  Average Accuracy: {avg_acc:.1f}%")
        print(f"  RMSE: {evaluation['rmse']:.3f}")
        print(f"  MAE: {evaluation['mae']:.3f}")
        print(f"  Correlation: {evaluation['correlation']:.3f}")

    # 汇总保存
    with open(f"{OUTPUT_DIR}/all_models_summary.json", 'w', encoding='utf-8') as f:
        json.dump({
            'experiment_info': {
                'timestamp': datetime.now().isoformat(),
                'n_models': len(MODELS_TO_TEST),
                'n_cves': len(valid_cves),
                'source_distribution': dict(source_stats)
            },
            'model_results': {
                m: {
                    'evaluation': all_results[m]['evaluation'],
                    'n_predictions': sum(1 for v in all_results[m]['predictions'].values() if is_valid_metrics(v))
                } for m in all_results
            }
        }, f, indent=2, ensure_ascii=False)

    # 只有有样本再画图
    if any(res['evaluation']['n_samples'] > 0 for res in all_results.values()):
        create_visualizations(all_results)
    else:
        print("\n[WARN] No successful predictions to visualize")

    print("\n" + "="*80)
    print("EXPERIMENT COMPLETED")
    print(f"Results saved to: {OUTPUT_DIR}")
    print("="*80)


if __name__ == "__main__":
    main()
