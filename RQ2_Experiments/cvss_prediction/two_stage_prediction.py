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

# 配置
REPORT_DIR = "./security-agent/cyber_data/cveList_V5/enhanced_threat_reports/2024/9xxx/"
GT_PATH = "./security-agent/cyber_data/cvss_2024_9xxx.json"
RESULTS_PATH = "./security-agent/cyber_data/two_stage_prediction_results.json"

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
    pattern_v3 = r'CVSS:3\.[01]/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])'
    match = re.search(pattern_v3, cvss_vector)
    
    if match:
        metrics_labels = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
        values = match.groups()
        return dict(zip(metrics_labels, values))
    
    # 支持CVSS 2.0格式: AV:N/AC:L/Au:S/C:P/I:P/A:P
    pattern_v2 = r'AV:([NAL])/AC:([LMH])/Au:([NSM])/C:([NPC])/I:([NPC])/A:([NPC])'
    match_v2 = re.search(pattern_v2, cvss_vector)
    
    if match_v2:
        av_v2, ac_v2, au_v2, c_v2, i_v2, a_v2 = match_v2.groups()
        
        # 转换映射 (CVSS 2.0 -> CVSS 3.1 近似)
        av_map = {'N': 'N', 'A': 'A', 'L': 'L'}
        ac_map = {'L': 'L', 'M': 'H', 'H': 'H'}
        pr_map = {'N': 'N', 'S': 'L', 'M': 'H'}
        ui = 'N'
        impact_map = {'N': 'N', 'P': 'L', 'C': 'H'}
        
        return {
            'AV': av_map.get(av_v2, 'N'),
            'AC': ac_map.get(ac_v2, 'L'), 
            'PR': pr_map.get(au_v2, 'L'),
            'UI': ui,
            'S': 'U',
            'C': impact_map.get(c_v2, 'L'),
            'I': impact_map.get(i_v2, 'L'),
            'A': impact_map.get(a_v2, 'L')
        }
    
    return None

def get_report(cveid):
    """获取威胁报告"""
    fn = os.path.join(REPORT_DIR, f"{cveid}_enhanced_report.txt")
    if os.path.exists(fn):
        with open(fn, "r", encoding="utf-8") as f:
            return f.read()
    return None

def stage1_classify_metrics_with_g4f(report, max_retries=3):
    """
    阶段1：使用g4f从威胁报告中分类CVSS metrics
    """
    prompt = f"""Analyze the following CVE threat report and classify each CVSS v3.1 metric.

**Instructions:**
Carefully read the threat report and determine the appropriate value for each CVSS v3.1 Base Metric:

**Attack Vector (AV):**
- N (Network): Can be exploited remotely over a network
- A (Adjacent): Requires adjacent network access (same subnet)
- L (Local): Requires local system access
- P (Physical): Requires physical access to the system

**Attack Complexity (AC):**
- L (Low): No special conditions or timing required
- H (High): Requires special conditions, timing, or social engineering

**Privileges Required (PR):**
- N (None): No privileges required
- L (Low): Basic user privileges required
- H (High): Administrative/high privileges required

**User Interaction (UI):**
- N (None): No user interaction needed
- R (Required): Requires user interaction (clicking, opening files, etc.)

**Scope (S):**
- U (Unchanged): Impact limited to the vulnerable component
- C (Changed): Impact extends beyond the vulnerable component

**Confidentiality Impact (C):**
- H (High): Total disclosure of information
- L (Low): Some information disclosure
- N (None): No confidentiality impact

**Integrity Impact (I):**
- H (High): Total compromise of system integrity
- L (Low): Some integrity compromise
- N (None): No integrity impact

**Availability Impact (A):**
- H (High): Total denial of service/system shutdown
- L (Low): Reduced performance/partial service disruption
- N (None): No availability impact

**CVE Threat Report:**
{report}

**Output Format:**
Respond with ONLY the metrics in this exact format:
AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X

Replace each X with the appropriate letter value. No explanation needed."""

    for attempt in range(max_retries):
        try:
            response = g4f.ChatCompletion.create(
                model=g4f.models.gpt_4o,
                messages=[{"role": "user", "content": prompt}],
                stream=False
            )
            
            # 解析metrics
            metrics = parse_metrics_from_gpt_response(response)
            if metrics:
                return metrics
            
            print(f"Warning: Could not parse metrics from response: {response}")
            
        except Exception as e:
            print(f"Stage 1 attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                sleep(random.uniform(2, 5))
    
    return None

def parse_metrics_from_gpt_response(response):
    """从GPT响应中解析CVSS metrics"""
    # 匹配标准格式: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    pattern = r"AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([HLN])\/I:([HLN])\/A:([HLN])"
    match = re.search(pattern, response)
    
    if match:
        metrics_labels = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
        values = match.groups()
        return dict(zip(metrics_labels, values))
    
    return None

def stage2_predict_score_from_metrics_with_g4f(metrics, max_retries=3):
    """
    阶段2：使用g4f基于分类的metrics预测CVSS分数
    """
    # 将metrics转换为可读格式
    metrics_readable = {
        'AV': {'N': 'Network', 'A': 'Adjacent Network', 'L': 'Local', 'P': 'Physical'}[metrics['AV']],
        'AC': {'L': 'Low', 'H': 'High'}[metrics['AC']],
        'PR': {'N': 'None', 'L': 'Low', 'H': 'High'}[metrics['PR']],
        'UI': {'N': 'None', 'R': 'Required'}[metrics['UI']],
        'S': {'U': 'Unchanged', 'C': 'Changed'}[metrics['S']],
        'C': {'H': 'High', 'L': 'Low', 'N': 'None'}[metrics['C']],
        'I': {'H': 'High', 'L': 'Low', 'N': 'None'}[metrics['I']],
        'A': {'H': 'High', 'L': 'Low', 'N': 'None'}[metrics['A']]
    }
    
    prompt = f"""Based on the following CVSS v3.1 Base Metrics, predict the CVSS Base Score (0.0 to 10.0).

**CVSS v3.1 Base Metrics:**
- Attack Vector: {metrics_readable['AV']} ({metrics['AV']})
- Attack Complexity: {metrics_readable['AC']} ({metrics['AC']})
- Privileges Required: {metrics_readable['PR']} ({metrics['PR']})
- User Interaction: {metrics_readable['UI']} ({metrics['UI']})
- Scope: {metrics_readable['S']} ({metrics['S']})
- Confidentiality Impact: {metrics_readable['C']} ({metrics['C']})
- Integrity Impact: {metrics_readable['I']} ({metrics['I']})
- Availability Impact: {metrics_readable['A']} ({metrics['A']})

**Instructions:**
Consider how these metrics combine to determine the overall severity:
- Higher exploitability (Network attack vector, Low complexity, No privileges/interaction required) increases the score
- Scope change amplifies the impact
- Higher impact on Confidentiality, Integrity, and Availability increases the score
- The score ranges from 0.0 (no impact) to 10.0 (critical severity)

**Output:**
Provide only a single number between 0.0 and 10.0 representing the CVSS Base Score. No explanation needed."""

    for attempt in range(max_retries):
        try:
            response = g4f.ChatCompletion.create(
                model=g4f.models.gpt_4o,
                messages=[{"role": "user", "content": prompt}],
                stream=False
            )
            
            # 提取数字
            pred_str = response.strip()
            numbers = re.findall(r'\d+\.?\d*', pred_str)
            if numbers:
                pred = float(numbers[0])
                if 0.0 <= pred <= 10.0:
                    return pred
            
            print(f"Warning: Invalid score format: {pred_str}")
            
        except Exception as e:
            print(f"Stage 2 attempt {attempt + 1} failed: {e}")
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
    
    metrics_stats = {}
    for metric in metrics_labels:
        metrics_stats[metric] = {'correct': 0, 'total': 0, 'distribution': Counter()}
    
    valid_predictions = 0
    
    for cveid, result in results.items():
        if (result.get('stage1_metrics') and 
            result.get('ground_truth_metrics') and 
            len(result['stage1_metrics']) == 8 and 
            len(result['ground_truth_metrics']) == 8):
            
            valid_predictions += 1
            
            for metric in metrics_labels:
                pred_val = result['stage1_metrics'].get(metric)
                gt_val = result['ground_truth_metrics'].get(metric)
                
                if pred_val and gt_val:
                    metrics_stats[metric]['total'] += 1
                    if pred_val == gt_val:
                        metrics_stats[metric]['correct'] += 1
                    
                    metrics_stats[metric]['distribution'][pred_val] += 1
    
    return metrics_stats, valid_predictions

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
    
    print("\nStarting two-stage prediction process...")
    
    for i, cveid in enumerate(tqdm(valid_cveids, desc="Processing CVE IDs")):
        # 跳过已经处理过的（但要统计它们）
        if cveid in existing_results and existing_results[cveid].get('stage2_score') is not None:
            scores_pred.append(existing_results[cveid]['stage2_score'])
            scores_gt.append(existing_results[cveid]['ground_truth_score'])
            successful_predictions += 1
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
        
        print(f"\nProcessing {cveid}...")
        
        # 阶段1：分类metrics
        stage1_metrics = stage1_classify_metrics_with_g4f(report)
        if not stage1_metrics:
            failed_predictions += 1
            print(f"  Stage 1 failed: Could not classify metrics")
            continue
        
        print(f"  Stage 1 success: {stage1_metrics}")
        
        # 阶段2：基于metrics预测分数
        stage2_score = stage2_predict_score_from_metrics_with_g4f(stage1_metrics)
        if stage2_score is None:
            failed_predictions += 1
            print(f"  Stage 2 failed: Could not predict score")
            continue
        
        print(f"  Stage 2 success: {stage2_score:.1f}")
        
        # 保存结果
        result = {
            'ground_truth_score': gt_score,
            'ground_truth_source': gt_source,
            'ground_truth_vector': gt_vector,
            'ground_truth_metrics': gt_metrics,
            'stage1_metrics': stage1_metrics,
            'stage2_score': stage2_score,
            'report_length': len(report),
            'processed': True
        }
        
        existing_results[cveid] = result
        
        scores_pred.append(stage2_score)
        scores_gt.append(gt_score)
        successful_predictions += 1
        
        print(f"  Final: Predicted={stage2_score:.1f}, GT={gt_score:.1f} ({gt_source})")
        print(f"  GT Metrics: {gt_metrics}")
        print(f"  Pred Metrics: {stage1_metrics}")
        
        # 每处理5个CVE就保存一次结果
        if (i + 1) % 5 == 0:
            save_results(existing_results)
        
        # 添加随机延迟避免被限制
        sleep(random.uniform(2, 4))
    
    # 保存最终结果
    save_results(existing_results)
    
    # 计算评估指标
    if len(scores_pred) > 0:
        scores_pred = np.array(scores_pred)
        scores_gt = np.array(scores_gt)
        
        rmse = np.sqrt(np.mean((scores_pred - scores_gt) ** 2))
        mae = np.mean(np.abs(scores_pred - scores_gt))
        correlation = np.corrcoef(scores_pred, scores_gt)[0,1]
        
        # 计算metrics准确率
        metrics_stats, valid_predictions = calculate_metrics_accuracy(existing_results)
        
        # 计算总体准确率
        total_correct = sum(stats['correct'] for stats in metrics_stats.values())
        total_predictions = sum(stats['total'] for stats in metrics_stats.values())
        overall_metrics_accuracy = total_correct / total_predictions * 100 if total_predictions > 0 else 0
        
        # 构建评估摘要
        evaluation_summary = {
            'timestamp': datetime.now().isoformat(),
            'method': 'Two-Stage LLM Prediction (Metrics Classification + Score Prediction)',
            'dataset_info': {
                'total_cve_ids': len(valid_cveids),
                'successful_predictions': successful_predictions,
                'failed_predictions': failed_predictions,
                'success_rate': successful_predictions/(successful_predictions+failed_predictions)*100 if (successful_predictions+failed_predictions) > 0 else 0
            },
            'score_prediction_metrics': {
                'rmse': float(rmse),
                'mae': float(mae),
                'correlation': float(correlation)
            },
            'metrics_classification_accuracy': {
                'overall_accuracy': overall_metrics_accuracy,
                'individual_metrics': {
                    metric: {
                        'name': {
                            'AV': 'Attack Vector', 'AC': 'Attack Complexity', 
                            'PR': 'Privileges Required', 'UI': 'User Interaction',
                            'S': 'Scope', 'C': 'Confidentiality',
                            'I': 'Integrity', 'A': 'Availability'
                        }.get(metric, metric),
                        'accuracy': stats['correct'] / stats['total'] * 100 if stats['total'] > 0 else 0,
                        'correct': stats['correct'],
                        'total': stats['total'],
                        'predicted_distribution': dict(stats['distribution'])
                    }
                    for metric, stats in metrics_stats.items() if stats['total'] > 0
                }
            },
            'score_distribution': {
                f"{range_start:.1f}-{range_start+3 if range_start < 9 else 10:.1f}": {
                    'ground_truth': int(np.sum((scores_gt >= range_start) & (scores_gt < (range_start+3 if range_start < 9 else 10)))),
                    'predicted': int(np.sum((scores_pred >= range_start) & (scores_pred < (range_start+3 if range_start < 9 else 10))))
                }
                for range_start in [0, 3, 7, 9]
            },
            'source_distribution': source_stats
        }
        
        print(f"\n{'='*80}")
        print("EVALUATION RESULTS - Two-Stage LLM Prediction")
        print(f"{'='*80}")
        print(f"Total CVE IDs processed: {len(valid_cveids)}")
        print(f"Successful predictions: {successful_predictions}")
        print(f"Failed predictions: {failed_predictions}")
        if (successful_predictions + failed_predictions) > 0:
            print(f"Success rate: {successful_predictions/(successful_predictions+failed_predictions)*100:.1f}%")
        else:
            print(f"Success rate: N/A (no predictions made)")
        print(f"RMSE: {rmse:.3f}")
        print(f"MAE: {mae:.3f}")
        print(f"Correlation: {correlation:.3f}")
        print(f"Overall Metrics Classification Accuracy: {overall_metrics_accuracy:.1f}%")
        print(f"{'='*80}")
        
        # 分析预测分布
        print("\nScore Distribution Analysis:")
        for range_start in [0, 3, 7, 9]:
            range_end = range_start + 3 if range_start < 9 else 10
            gt_in_range = np.sum((scores_gt >= range_start) & (scores_gt < range_end))
            pred_in_range = np.sum((scores_pred >= range_start) & (scores_pred < range_end))
            print(f"  {range_start:.1f}-{range_end:.1f}: GT={gt_in_range}, Pred={pred_in_range}")
        
        # 详细的metrics分析
        print(f"\n{'='*80}")
        print("METRICS CLASSIFICATION ANALYSIS")
        print(f"{'='*80}")
        for metric, stats in metrics_stats.items():
            if stats['total'] > 0:
                accuracy = stats['correct'] / stats['total'] * 100
                metric_name = {
                    'AV': 'Attack Vector', 'AC': 'Attack Complexity', 
                    'PR': 'Privileges Required', 'UI': 'User Interaction',
                    'S': 'Scope', 'C': 'Confidentiality',
                    'I': 'Integrity', 'A': 'Availability'
                }.get(metric, metric)
                
                print(f"{metric} ({metric_name})")
                print(f"  Accuracy: {accuracy:.1f}% ({stats['correct']}/{stats['total']})")
                print(f"  Predicted values: {dict(stats['distribution'])}")
        
        # 保存结果和摘要
        save_results(existing_results, evaluation_summary)
    
    else:
        print("No successful predictions to evaluate!")

if __name__ == "__main__":
    main()