import os
import json
import numpy as np
import g4f
import re
from time import sleep
import random

from tqdm import tqdm
from collections import Counter

# 配置
REPORT_DIR = "./security-agent/cyber_data/cveList_V5/enhanced_threat_reports/2024/9xxx/"
GT_PATH = "./security-agent/cyber_data/cvss_2024_9xxx.json"
RESULTS_PATH = "./security-agent/cyber_data/metrics_prediction_results.json"

# CVSS v3.1 评分公式实现
def cvss3_base_score(metrics):
    """
    根据8个CVSS metrics计算base score
    metrics: dict {'AV':'N', 'AC':'L', 'PR':'N', 'UI':'N', 'S':'U', 'C':'H', 'I':'H', 'A':'H'}
    """
    # 指标值对照表
    AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    AC = {'L': 0.77, 'H': 0.44}
    PR = {'N': {'U': 0.85, 'C': 0.85}, 'L': {'U': 0.62, 'C': 0.68}, 'H': {'U': 0.27, 'C': 0.5}}
    UI = {'N': 0.85, 'R': 0.62}
    S = {'U': 'U', 'C': 'C'}
    C = {'H': 0.56, 'L': 0.22, 'N': 0.0}
    I = C.copy()
    A = C.copy()
    
    try:
        av = AV[metrics['AV']]
        ac = AC[metrics['AC']]
        pr = PR[metrics['PR']][metrics['S']]
        ui = UI[metrics['UI']]
        s = S[metrics['S']]
        c = C[metrics['C']]
        i = I[metrics['I']]
        a = A[metrics['A']]
        
        # 计算impact
        impact = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if s == 'U':
            impact_score = 6.42 * impact
        else:
            impact_score = 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15
        
        # 计算exploitability
        exploitab = 8.22 * av * ac * pr * ui
        
        # 计算base score
        if impact <= 0:
            base_score = 0
        else:
            if s == 'U':
                base_score = min(impact_score + exploitab, 10)
            else:
                base_score = min(1.08 * (impact_score + exploitab), 10)
        
        return round(base_score, 1)
    
    except (KeyError, ValueError) as e:
        print(f"Error calculating CVSS score: {e}, metrics: {metrics}")
        return None

# 加载ground truth
print("Loading ground truth data...")
with open(GT_PATH, "r", encoding="utf-8") as f:
    gt_all = json.load(f)

def get_best_score_and_vector(cveid):
    """获取最佳评分和对应的CVSS向量，优先级：NIST > Wordfence > 其他"""
    items = gt_all.get(cveid, [])
    
    # 优先查找NIST
    for x in items:
        if (x.get("score_source") == "NIST" and 
            x.get("base_score") is not None and 
            x.get("cvss_vector")):
            return float(x["base_score"]), x["cvss_vector"], "NIST"
    
    # 如果没有NIST，查找Wordfence
    for x in items:
        if (x.get("score_source") == "Wordfence" and 
            x.get("base_score") is not None and 
            x.get("cvss_vector")):
            return float(x["base_score"]), x["cvss_vector"], "Wordfence"
    
    # 如果都没有，返回第一个有效的
    for x in items:
        if x.get("base_score") is not None and x.get("cvss_vector"):
            return float(x["base_score"]), x["cvss_vector"], x.get("score_source", "Unknown")
    
    return None, None, None

def parse_cvss_vector_to_metrics(cvss_vector):
    """从CVSS向量字符串解析出metrics"""
    if not cvss_vector:
        return None
        
    # 支持CVSS 3.0/3.1格式: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
    pattern = r'CVSS:3\.[01]/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])'
    match = re.search(pattern, cvss_vector)
    
    if match:
        metrics_labels = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
        values = match.groups()
        return dict(zip(metrics_labels, values))
    
    return None

def get_report(cveid):
    """获取威胁报告"""
    fn = os.path.join(REPORT_DIR, f"{cveid}_enhanced_report.txt")
    if os.path.exists(fn):
        with open(fn, "r", encoding="utf-8") as f:
            return f.read()
    return None

def parse_metrics_from_gpt(text):
    """从GPT响应中解析CVSS metrics"""
    # 匹配标准格式: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    pattern = r"AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([HLN])\/I:([HLN])\/A:([HLN])"
    match = re.search(pattern, text)
    
    if match:
        metrics_labels = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
        values = match.groups()
        return dict(zip(metrics_labels, values))
    
    # 备用解析方法：逐个查找
    metrics = {}
    patterns = {
        'AV': r'AV[:\s]*([NALP])',
        'AC': r'AC[:\s]*([LH])',
        'PR': r'PR[:\s]*([NLH])',
        'UI': r'UI[:\s]*([NR])',
        'S': r'S[:\s]*([UC])',
        'C': r'C[:\s]*([HLN])',
        'I': r'I[:\s]*([HLN])',
        'A': r'A[:\s]*([HLN])'
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            metrics[key] = match.group(1).upper()
    
    # 检查是否所有metrics都找到了
    if len(metrics) == 8:
        return metrics
    
    print(f"Warning: Could not parse all metrics from: {text}")
    return None

def predict_metrics_with_g4f(report, max_retries=3):
    """使用g4f预测CVSS metrics"""
    prompt = f"""Analyze the following CVE threat report and determine the CVSS v3.1 Base Metrics.

For each metric, choose the appropriate value:

**Attack Vector (AV):**
- N (Network): Remotely exploitable
- A (Adjacent): Adjacent network access required  
- L (Local): Local access required
- P (Physical): Physical access required

**Attack Complexity (AC):**
- L (Low): No special conditions
- H (High): Requires special conditions/timing

**Privileges Required (PR):**
- N (None): No privileges needed
- L (Low): Basic user privileges needed
- H (High): Admin/high privileges needed

**User Interaction (UI):**
- N (None): No user interaction needed
- R (Required): Requires user interaction

**Scope (S):**
- U (Unchanged): Impact limited to vulnerable component
- C (Changed): Impact extends beyond vulnerable component

**Confidentiality Impact (C):**
- H (High): Total information disclosure
- L (Low): Some information disclosure
- N (None): No confidentiality impact

**Integrity Impact (I):**
- H (High): Total compromise of system integrity
- L (Low): Some integrity impact
- N (None): No integrity impact

**Availability Impact (A):**
- H (High): Total shutdown/denial of service
- L (Low): Reduced performance/availability
- N (None): No availability impact

CVE Report:
{report}

Answer in this exact format: AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X

Replace X with the appropriate values. No explanation needed, only the metrics string."""

    for attempt in range(max_retries):
        try:
            response = g4f.ChatCompletion.create(
                model=g4f.models.gpt_4o,
                messages=[{"role": "user", "content": prompt}],
                stream=False
            )
            
            metrics = parse_metrics_from_gpt(response)
            if metrics:
                return metrics
            
            print(f"Warning: Could not parse metrics from response: {response}")
            
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                sleep(random.uniform(2, 5))
    
    return None

def load_existing_results():
    """加载已有的预测结果"""
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_results(results, evaluation_summary=None):
    """保存预测结果和评估摘要"""
    # 保存预测结果
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # 如果有评估摘要，保存到单独的文件
    if evaluation_summary:
        summary_path = RESULTS_PATH.replace('.json', '_summary.json')
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(evaluation_summary, f, indent=2, ensure_ascii=False)
        print(f"Evaluation summary saved to: {summary_path}")

def calculate_metrics_accuracy(results):
    """计算每个metric的准确率"""
    metrics_labels = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
    
    # 统计每个metric的正确和总数
    metrics_stats = {}
    for metric in metrics_labels:
        metrics_stats[metric] = {'correct': 0, 'total': 0, 'distribution': Counter()}
    
    valid_predictions = 0
    
    for cveid, result in results.items():
        if (result.get('predicted_metrics') and 
            result.get('ground_truth_metrics') and 
            len(result['predicted_metrics']) == 8 and 
            len(result['ground_truth_metrics']) == 8):
            
            valid_predictions += 1
            
            for metric in metrics_labels:
                pred_val = result['predicted_metrics'].get(metric)
                gt_val = result['ground_truth_metrics'].get(metric)
                
                if pred_val and gt_val:
                    metrics_stats[metric]['total'] += 1
                    if pred_val == gt_val:
                        metrics_stats[metric]['correct'] += 1
                    
                    # 统计预测分布
                    metrics_stats[metric]['distribution'][pred_val] += 1
    
    return metrics_stats, valid_predictions

def print_detailed_metrics_analysis(results):
    """打印详细的metrics分析结果并返回统计数据"""
    metrics_stats, valid_predictions = calculate_metrics_accuracy(results)
    
    print(f"\n{'='*80}")
    print("DETAILED METRICS ACCURACY ANALYSIS")
    print(f"{'='*80}")
    print(f"Valid predictions with complete metrics: {valid_predictions}")
    
    # 计算总体准确率
    total_correct = sum(stats['correct'] for stats in metrics_stats.values())
    total_predictions = sum(stats['total'] for stats in metrics_stats.values())
    overall_accuracy = total_correct / total_predictions * 100 if total_predictions > 0 else 0
    
    print(f"Overall metrics accuracy: {overall_accuracy:.1f}%")
    print(f"{'='*80}")
    
    # 每个metric的详细分析
    metrics_details = {}
    for metric, stats in metrics_stats.items():
        if stats['total'] > 0:
            accuracy = stats['correct'] / stats['total'] * 100
            metric_name = {
                'AV': 'Attack Vector',
                'AC': 'Attack Complexity', 
                'PR': 'Privileges Required',
                'UI': 'User Interaction',
                'S': 'Scope',
                'C': 'Confidentiality',
                'I': 'Integrity',
                'A': 'Availability'
            }.get(metric, metric)
            
            print(f"\n{metric} ({metric_name})")
            print(f"  Accuracy: {accuracy:.1f}% ({stats['correct']}/{stats['total']})")
            print(f"  Predicted values: {dict(stats['distribution'])}")
            
            # 保存到结果中
            metrics_details[metric] = {
                'name': metric_name,
                'accuracy': accuracy,
                'correct': stats['correct'],
                'total': stats['total'],
                'predicted_distribution': dict(stats['distribution'])
            }
    
    return metrics_stats, overall_accuracy, metrics_details

def analyze_error_patterns(results):
    """分析错误模式并返回统计数据"""
    print(f"\n{'='*80}")
    print("ERROR PATTERN ANALYSIS")
    print(f"{'='*80}")
    
    error_patterns = {}
    
    for cveid, result in results.items():
        if (result.get('predicted_metrics') and 
            result.get('ground_truth_metrics')):
            
            pred = result['predicted_metrics']
            gt = result['ground_truth_metrics']
            
            for metric in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
                if pred.get(metric) and gt.get(metric) and pred[metric] != gt[metric]:
                    error_key = f"{metric}: {gt[metric]} -> {pred[metric]}"
                    error_patterns[error_key] = error_patterns.get(error_key, 0) + 1
    
    # 显示最常见的错误
    print("Most common prediction errors:")
    sorted_errors = sorted(error_patterns.items(), key=lambda x: x[1], reverse=True)
    for error, count in sorted_errors[:15]:  # 显示前15个最常见错误
        print(f"  {error}: {count} times")
    
    return dict(sorted_errors[:15])  # 返回前15个最常见错误

def main():
    # 获取所有有效的CVE ID
    print("Filtering CVE IDs with valid scores and vectors...")
    valid_cveids = []
    source_stats = {}
    
    for cveid in gt_all:
        score, vector, source = get_best_score_and_vector(cveid)
        if score is not None and vector is not None:
            valid_cveids.append(cveid)
            source_stats[source] = source_stats.get(source, 0) + 1
    
    print(f"Found {len(valid_cveids)} CVE IDs with valid scores and vectors")
    print("Score source distribution:")
    for source, count in sorted(source_stats.items()):
        print(f"  {source}: {count}")
    
    # 加载已有结果
    existing_results = load_existing_results()
    
    scores_gt = []
    scores_pred = []
    successful_predictions = 0
    failed_predictions = 0
    
    print("\nStarting metrics prediction process...")
    
    for i, cveid in enumerate(tqdm(valid_cveids, desc="Processing CVE IDs")):
        # 跳过已经处理过的
        if cveid in existing_results:
            if existing_results[cveid].get('predicted_score') is not None:
                scores_pred.append(existing_results[cveid]['predicted_score'])
                scores_gt.append(existing_results[cveid]['ground_truth_score'])
                continue
        
        # 获取报告
        report = get_report(cveid)
        if not report:
            print(f"No report found for {cveid}")
            continue
        
        # 获取ground truth
        gt_score, gt_vector, gt_source = get_best_score_and_vector(cveid)
        if gt_score is None or gt_vector is None:
            continue
        
        # 解析ground truth metrics
        gt_metrics = parse_cvss_vector_to_metrics(gt_vector)
        if not gt_metrics:
            print(f"Could not parse GT vector for {cveid}: {gt_vector}")
            continue
        
        # 预测metrics
        predicted_metrics = predict_metrics_with_g4f(report)
        
        if predicted_metrics:
            # 计算base score
            pred_score = cvss3_base_score(predicted_metrics)
            
            if pred_score is not None:
                scores_pred.append(pred_score)
                scores_gt.append(gt_score)
                successful_predictions += 1
                
                # 保存结果
                result = {
                    'ground_truth_score': gt_score,
                    'ground_truth_source': gt_source,
                    'ground_truth_vector': gt_vector,
                    'ground_truth_metrics': gt_metrics,
                    'predicted_metrics': predicted_metrics,
                    'predicted_score': pred_score,
                    'report_length': len(report),
                    'processed': True
                }
                
                existing_results[cveid] = result
                print(f"{cveid}: Predicted={pred_score:.1f}, GT={gt_score:.1f} ({gt_source})")
                print(f"  GT Metrics: {gt_metrics}")
                print(f"  Pred Metrics: {predicted_metrics}")
            else:
                failed_predictions += 1
                print(f"{cveid}: Score calculation failed, GT={gt_score:.1f} ({gt_source})")
        else:
            failed_predictions += 1
            print(f"{cveid}: Metrics prediction failed, GT={gt_score:.1f} ({gt_source})")
        
        # 每处理10个CVE就保存一次结果
        if (i + 1) % 10 == 0:
            save_results(existing_results)
        
        # 添加随机延迟避免被限制
        sleep(random.uniform(1, 3))
    
    # 保存最终结果
    save_results(existing_results)
    
    # 计算评估指标
    if len(scores_pred) > 0:
        scores_pred = np.array(scores_pred)
        scores_gt = np.array(scores_gt)
        
        rmse = np.sqrt(np.mean((scores_pred - scores_gt) ** 2))
        mae = np.mean(np.abs(scores_pred - scores_gt))
        
        print(f"\n{'='*80}")
        print("EVALUATION RESULTS - Base Score via Metrics")
        print(f"{'='*80}")
        print(f"Total CVE IDs processed: {len(valid_cveids)}")
        print(f"Successful predictions: {successful_predictions}")
        print(f"Failed predictions: {failed_predictions}")
        print(f"Success rate: {successful_predictions/(successful_predictions+failed_predictions)*100:.1f}%")
        print(f"RMSE: {rmse:.3f}")
        print(f"MAE: {mae:.3f}")
        print(f"Correlation: {np.corrcoef(scores_pred, scores_gt)[0,1]:.3f}")
        
        # 分析预测分布
        print("\nScore Distribution Analysis:")
        for range_start in [0, 3, 7, 9]:
            range_end = range_start + 3 if range_start < 9 else 10
            gt_in_range = np.sum((scores_gt >= range_start) & (scores_gt < range_end))
            pred_in_range = np.sum((scores_pred >= range_start) & (scores_pred < range_end))
            print(f"  {range_start:.1f}-{range_end:.1f}: GT={gt_in_range}, Pred={pred_in_range}")
        
        # 详细的metrics准确率分析
        metrics_stats, overall_metrics_accuracy, metrics_details = print_detailed_metrics_analysis(existing_results)
        
        # 错误模式分析
        error_patterns = analyze_error_patterns(existing_results)
        
        # 构建评估摘要
        evaluation_summary = {
            'timestamp': str(pd.Timestamp.now()) if 'pd' in globals() else str(datetime.now()),
            'dataset_info': {
                'total_cve_ids': len(valid_cveids),
                'successful_predictions': successful_predictions,
                'failed_predictions': failed_predictions,
                'success_rate': successful_predictions/(successful_predictions+failed_predictions)*100
            },
            'score_prediction_metrics': {
                'rmse': float(rmse),
                'mae': float(mae),
                'correlation': float(np.corrcoef(scores_pred, scores_gt)[0,1])
            },
            'metrics_accuracy': {
                'overall_accuracy': overall_metrics_accuracy,
                'individual_metrics': metrics_details
            },
            'score_distribution': {
                f"{range_start:.1f}-{range_start+3 if range_start < 9 else 10:.1f}": {
                    'ground_truth': int(np.sum((scores_gt >= range_start) & (scores_gt < (range_start+3 if range_start < 9 else 10)))),
                    'predicted': int(np.sum((scores_pred >= range_start) & (scores_pred < (range_start+3 if range_start < 9 else 10))))
                }
                for range_start in [0, 3, 7, 9]
            },
            'common_errors': error_patterns,
            'source_distribution': source_stats
        }
        
        # 总结
        print(f"\n{'='*80}")
        print("SUMMARY")
        print(f"{'='*80}")
        print(f"Score Prediction RMSE: {rmse:.3f}")
        print(f"Score Prediction MAE: {mae:.3f}")
        print(f"Score Correlation: {np.corrcoef(scores_pred, scores_gt)[0,1]:.3f}")
        print(f"Overall Metrics Accuracy: {overall_metrics_accuracy:.1f}%")
        print(f"{'='*80}")
        
        # 保存结果和摘要
        save_results(existing_results, evaluation_summary)
    
    else:
        print("No successful predictions to evaluate!")

if __name__ == "__main__":
    main()