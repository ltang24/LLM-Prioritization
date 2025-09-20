import os
import json
import numpy as np
import g4f
from time import sleep
import random
from tqdm import tqdm
from datetime import datetime

# 配置
REPORT_DIR = "./security-agent/cyber_data/cveList_V5/enhanced_threat_reports/2024/9xxx/"
GT_PATH = "./security-agent/cyber_data/cvss_2024_9xxx.json"
RESULTS_PATH = "./security-agent/cyber_data/prediction_results2.json"

# 加载ground truth
print("Loading ground truth data...")
with open(GT_PATH, "r", encoding="utf-8") as f:
    gt_all = json.load(f)

def get_best_score(cveid):
    """
    获取最佳评分，优先级：NIST > Wordfence > 其他
    """
    items = gt_all.get(cveid, [])
    
    # 优先查找NIST
    for x in items:
        if x.get("score_source") == "NIST" and x.get("base_score") is not None:
            return float(x["base_score"]), "NIST"
    
    # 如果没有NIST，查找Wordfence
    for x in items:
        if x.get("score_source") == "Wordfence" and x.get("base_score") is not None:
            return float(x["base_score"]), "Wordfence"
    
    # 如果都没有，返回第一个有效分数
    for x in items:
        if x.get("base_score") is not None:
            return float(x["base_score"]), x.get("score_source", "Unknown")
    
    return None, None

def get_report(cveid):
    """获取威胁报告"""
    fn = os.path.join(REPORT_DIR, f"{cveid}_enhanced_report.txt")
    if os.path.exists(fn):
        with open(fn, "r", encoding="utf-8") as f:
            return f.read()
    return None

def predict_score_with_g4f(report, max_retries=3):
    """
    使用g4f预测CVSS分数
    """
    prompt = f"""Read the following CVE threat report and predict the CVSS v3.1 Base Score (0.0 to 10.0).

Consider these factors:
- Attack Vector (Network/Adjacent/Local/Physical)
- Attack Complexity (Low/High)
- Privileges Required (None/Low/High)
- User Interaction (None/Required)
- Scope (Unchanged/Changed)
- Impact on Confidentiality, Integrity, Availability (None/Low/High)

Report:
{report}

Answer only with a single number between 0.0 and 10.0, no explanation."""

    for attempt in range(max_retries):
        try:
            response = g4f.ChatCompletion.create(
                model=g4f.models.gpt_4o,  # 或者使用其他模型如 gpt_35_turbo
                messages=[{"role": "user", "content": prompt}],
                stream=False
            )
            
            # 提取数字
            pred_str = response.strip()
            # 尝试提取第一个数字
            import re
            numbers = re.findall(r'\d+\.?\d*', pred_str)
            if numbers:
                pred = float(numbers[0])
                if 0.0 <= pred <= 10.0:
                    return pred
            
            print(f"Warning: Invalid prediction format: {pred_str}")
            
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                sleep(random.uniform(2, 5))  # 随机延迟
            
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

def main():
    # 获取所有有效的CVE ID
    print("Filtering CVE IDs with valid scores...")
    valid_cveids = []
    source_stats = {}
    
    for cveid in gt_all:
        score, source = get_best_score(cveid)
        if score is not None:
            valid_cveids.append(cveid)
            source_stats[source] = source_stats.get(source, 0) + 1
    
    print(f"Found {len(valid_cveids)} CVE IDs with valid scores")
    print("Score source distribution:")
    for source, count in sorted(source_stats.items()):
        print(f"  {source}: {count}")
    
    # 加载已有结果
    existing_results = load_existing_results()
    
    scores_gt = []
    scores_pred = []
    successful_predictions = 0
    failed_predictions = 0
    
    print("\nStarting prediction process...")
    
    for i, cveid in enumerate(tqdm(valid_cveids, desc="Processing CVE IDs")):
        # 跳过已经处理过的（但要统计它们）
        if cveid in existing_results and existing_results[cveid].get('predicted_score') is not None:
            scores_pred.append(existing_results[cveid]['predicted_score'])
            scores_gt.append(existing_results[cveid]['ground_truth_score'])
            successful_predictions += 1
            continue
        
        # 获取报告
        report = get_report(cveid)
        if not report:
            print(f"No report found for {cveid}")
            continue
        
        # 获取ground truth
        gt_score, gt_source = get_best_score(cveid)
        if gt_score is None:
            continue
        
        # 预测分数
        pred_score = predict_score_with_g4f(report)
        
        # 保存结果
        result = {
            'ground_truth_score': gt_score,
            'ground_truth_source': gt_source,
            'predicted_score': pred_score,
            'report_length': len(report),
            'processed': True
        }
        
        existing_results[cveid] = result
        
        if pred_score is not None:
            scores_pred.append(pred_score)
            scores_gt.append(gt_score)
            successful_predictions += 1
            print(f"{cveid}: Predicted={pred_score:.1f}, GT={gt_score:.1f} ({gt_source})")
        else:
            failed_predictions += 1
            print(f"{cveid}: Prediction failed, GT={gt_score:.1f} ({gt_source})")
        
        # 每处理10个CVE就保存一次结果
        if (i + 1) % 10 == 0:
            save_results(existing_results)
        
        # 添加随机延迟避免被限制
        sleep(random.uniform(1, 3))
    
    # 计算评估指标
    if len(scores_pred) > 0:
        scores_pred = np.array(scores_pred)
        scores_gt = np.array(scores_gt)
        
        rmse = np.sqrt(np.mean((scores_pred - scores_gt) ** 2))
        mae = np.mean(np.abs(scores_pred - scores_gt))
        correlation = np.corrcoef(scores_pred, scores_gt)[0,1]
        
        # 构建评估摘要
        evaluation_summary = {
            'timestamp': datetime.now().isoformat(),
            'method': 'Direct Score Prediction',
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
            'score_distribution': {
                f"{range_start:.1f}-{range_start+3 if range_start < 9 else 10:.1f}": {
                    'ground_truth': int(np.sum((scores_gt >= range_start) & (scores_gt < (range_start+3 if range_start < 9 else 10)))),
                    'predicted': int(np.sum((scores_pred >= range_start) & (scores_pred < (range_start+3 if range_start < 9 else 10))))
                }
                for range_start in [0, 3, 7, 9]
            },
            'source_distribution': source_stats
        }
        
        print(f"\n{'='*50}")
        print("EVALUATION RESULTS")
        print(f"{'='*50}")
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
        print(f"{'='*50}")
        
        # 分析预测分布
        print("\nScore Distribution Analysis:")
        for range_start in [0, 3, 7, 9]:
            range_end = range_start + 3 if range_start < 9 else 10
            gt_in_range = np.sum((scores_gt >= range_start) & (scores_gt < range_end))
            pred_in_range = np.sum((scores_pred >= range_start) & (scores_pred < range_end))
            print(f"  {range_start:.1f}-{range_end:.1f}: GT={gt_in_range}, Pred={pred_in_range}")
        
        # 保存结果和摘要
        save_results(existing_results, evaluation_summary)
    
    else:
        print("No successful predictions to evaluate!")

if __name__ == "__main__":
    main()