#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

# ====== 参数配置（可按需调整） ======
FILE_PATH = '/home/xiaoqun/RQ3_Experimants/epss_analysis/epss_history.json'

# 将“稳定/轻微波动”合并为一类的阈值
STABLE_THRESHOLD = 0.001     # 极稳定阈值：max-min < 0.001
MILD_THRESHOLD   = 0.01      # 轻微波动阈值：范围 < 0.01 也视为 stable

# 判定“突变”的最小跳变（相邻两点差值阈值），用于辅助解释
JUMP_THRESHOLD   = 0.10

REPORT_PREFIX = "epss_trend_report"
IMG_PREFIX    = "epss_trend_analysis"
JSON_PREFIX   = "epss_trend"

# Matplotlib 设置
plt.rcParams['font.family'] = ['Arial', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['figure.figsize'] = (14, 6)


# ========= 核心函数：趋势分析（4类） =========
def analyze_epss_changes(
    cve_data,
    stable_threshold=0.001,   # 极稳定：range < 0.001
    mild_threshold=0.01,      # 非单调但总体波动很小，也算 stable 的上限
    jump_threshold=0.10,      # “突变”判定：任意相邻两点绝对差 > 0.10
    net_threshold=1e-4,       # “总体增/减”所需最小首末净变化阈值（0.0001）
    majority_ratio=0.60       # 上升/下降步数占比阈值（60%）
):
    """
    四类趋势（总体趋势判法）：
      - 'stable'               : 极稳定；或非单调但整体波动小（range < mild_threshold）
      - 'monotonic_increase'   : 总体向上（首末净增 > net_threshold 且 上升步数占比 >= majority_ratio）
      - 'monotonic_decrease'   : 总体向下（首末净减 < -net_threshold 且 下降步数占比 >= majority_ratio）
      - 'sudden_change'        : 存在大跳变，或整体波动较大且不满足总体增/减
    """
    history = cve_data.get('epss_history', [])
    if not history or len(history) < 2:
        return None

    # 取并排序
    try:
        scores = [float(h['new_score']) for h in history]
        dates  = [datetime.strptime(h['date'], '%Y-%m-%d') for h in history]
        dates, scores = zip(*sorted(zip(dates, scores)))
    except Exception:
        return None

    scores = np.asarray(scores, dtype=float)
    diffs  = np.diff(scores)
    abs_diffs = np.abs(diffs)

    max_score   = float(scores.max())
    min_score   = float(scores.min())
    score_range = max_score - min_score
    max_jump    = float(abs_diffs.max()) if len(abs_diffs) else 0.0

    first_score = float(scores[0])
    last_score  = float(scores[-1])
    net_change  = last_score - first_score

    # 步数统计（忽略为0的步）
    pos_steps = int(np.sum(diffs > 0))
    neg_steps = int(np.sum(diffs < 0))
    eff_steps = pos_steps + neg_steps
    pos_ratio = (pos_steps / eff_steps) if eff_steps > 0 else 0.0
    neg_ratio = (neg_steps / eff_steps) if eff_steps > 0 else 0.0

    # 1) 极稳定（优先）
    if score_range < stable_threshold and max_jump < stable_threshold:
        trend = "stable"

    # 2) 明显突变
    elif max_jump >= jump_threshold:
        trend = "sudden_change"

    else:
        # 3) 总体趋势（首末净变化 + 步数占比）
        if net_change > net_threshold and pos_ratio >= majority_ratio:
            trend = "monotonic_increase"
        elif net_change < -net_threshold and neg_ratio >= majority_ratio:
            trend = "monotonic_decrease"
        else:
            # 4) 非单调但波动很小 -> stable；否则 -> sudden_change
            trend = "stable" if score_range < mild_threshold else "sudden_change"

    return {
        'cve_id': cve_data.get('cve_id', ''),
        'trend': trend,
        'max_score': max_score,
        'min_score': min_score,
        'score_range': score_range,
        'max_jump': max_jump,
        'first_date': dates[0].strftime('%Y-%m-%d'),
        'last_date': dates[-1].strftime('%Y-%m-%d'),
        'first_score': first_score,
        'last_score': last_score,
        'net_change': net_change,
        'pos_steps': pos_steps,
        'neg_steps': neg_steps,
        'pos_ratio': pos_ratio,
        'neg_ratio': neg_ratio,
        'steps': int(len(scores)),
        'original_data': cve_data
    }



# ========= 保存按趋势分类的 JSON =========
def save_classified_json(df, timestamp_str):
    """按 trend(4类) 导出 JSON"""
    print("\n正在保存趋势分类 JSON 文件...")
    for trend_type in ['stable', 'monotonic_increase', 'monotonic_decrease', 'sudden_change']:
        sub = df[df['trend'] == trend_type]
        out = {row['cve_id']: row['original_data'] for _, row in sub.iterrows()}
        filename = f"{JSON_PREFIX}_{trend_type}_{timestamp_str}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"✅ {trend_type} -> {filename} ({len(out)} 条)")


# ========= 可视化：四类趋势 =========
def draw_beautiful_chart(stable_count, mono_inc_count, mono_dec_count, sudden_count, total_cves):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 7))

    # 饼图：4 类趋势分布
    pattern_data = [
        ('Stable', stable_count, '#95a5a6'),
        ('↑ Monotonic Increase', mono_inc_count, '#2ecc71'),
        ('↓ Monotonic Decrease', mono_dec_count, '#e74c3c'),
        ('Sudden Change', sudden_count, '#f39c12'),
    ]
    non_zero = [(l, c, col) for (l, c, col) in pattern_data if c > 0]
    if non_zero:
        labels, values, colors = zip(*non_zero)
        wedges, texts, autotexts = ax1.pie(
            values, labels=labels, autopct='%1.1f%%', startangle=90,
            colors=colors, textprops={'fontsize': 11, 'weight': 'bold'},
            explode=[0.05] * len(values)
        )
        for t in autotexts:
            t.set_color('white'); t.set_fontsize(10); t.set_weight('bold')
    else:
        ax1.text(0.5, 0.5, 'No Data Found', ha='center', va='center',
                 fontsize=14, weight='bold')
    ax1.set_title('EPSS Trend Distribution', fontsize=16, fontweight='bold', pad=20)

    # 柱状图：数量
    categories = ['Stable', '↑ Mono. Inc', '↓ Mono. Dec', 'Sudden']
    counts = [stable_count, mono_inc_count, mono_dec_count, sudden_count]
    colors = ['#95a5a6', '#2ecc71', '#e74c3c', '#f39c12']

    bars = ax2.bar(categories, counts, color=colors, edgecolor='white',
                   linewidth=2, alpha=0.85, width=0.6)
    ax2.set_ylabel('Number of CVEs', fontsize=14, fontweight='bold')
    ax2.set_title('CVE Trend Classification', fontsize=16, fontweight='bold', pad=20)
    ax2.grid(axis='y', linestyle='--', alpha=0.3); ax2.set_axisbelow(True)
    for bar, count in zip(bars, counts):
        percent = (count / total_cves * 100) if total_cves else 0
        h = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width() / 2,
                 h + max(1, total_cves * 0.02),
                 f"{count}\n({percent:.1f}%)",
                 ha='center', va='bottom', fontsize=12, fontweight='bold')
    ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)
    ax2.tick_params(axis='both', which='major', labelsize=12)

    plt.tight_layout()
    nowstr = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname = f"{IMG_PREFIX}_{nowstr}.png"
    plt.savefig(fname, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ 图表已保存到: {fname}")
    plt.show()


# ========= 主流程 =========
def main():
    print("正在分析 EPSS 数据...")

    # 1) 读取数据
    try:
        with open(FILE_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"✅ 成功读取数据文件，包含 {len(data)} 个 CVE 记录")
    except Exception as e:
        print(f"❌ 读取文件失败: {e}")
        return

    # 2) 分析趋势
    rows, failed = [], 0
    for cve_id, cve_data in data.items():
        res = analyze_epss_changes(cve_data)
        if res:
            rows.append(res)
        else:
            failed += 1
    if not rows:
        print("❌ 没有有效数据"); return

    df = pd.DataFrame(rows)
    print(f"✅ 成功分析 {len(df)} 个 CVE，跳过 {failed} 个无效记录")

    # 3) 统计 4 类趋势
    trend_counts = df['trend'].value_counts().to_dict()
    stable_count   = trend_counts.get('stable', 0)
    mono_inc_count = trend_counts.get('monotonic_increase', 0)
    mono_dec_count = trend_counts.get('monotonic_decrease', 0)
    sudden_count   = trend_counts.get('sudden_change', 0)
    total_cves     = len(df)

    # 4) 打印汇总
    print("\n📊 趋势分类统计：")
    print(f"• Stable（稳定/轻微波动）: {stable_count}")
    print(f"• Monotonic Increase（单调增）: {mono_inc_count}")
    print(f"• Monotonic Decrease（单调减）: {mono_dec_count}")
    print(f"• Sudden Change（突变）: {sudden_count}")

    # 5) 生成时间戳用于文件命名
    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')

    # 6) 保存分类 JSON
    save_classified_json(df, timestamp_str)

    # 7) 生成文字报告
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_content = [
        "EPSS 趋势分析报告（四类）",
        f"分析时间: {now_str}",
        f"数据源: {FILE_PATH}",
        f"总分析 CVE 数: {total_cves}",
        "",
        "【分类定义阈值】",
        f"- 稳定/轻微波动: range < {MILD_THRESHOLD}（其中极稳定: < {STABLE_THRESHOLD}）",
        f"- 突变参考跳变阈值: 任意相邻两点差 > {JUMP_THRESHOLD}",
        "",
        "【趋势统计】",
        f"- Stable: {stable_count}",
        f"- Monotonic Increase: {mono_inc_count}",
        f"- Monotonic Decrease: {mono_dec_count}",
        f"- Sudden Change: {sudden_count}",
        "",
        "【变化范围统计】",
        f"- 最大变化: {df['score_range'].max():.4f}",
        f"- 最小变化: {df['score_range'].min():.4f}",
        f"- 平均变化: {df['score_range'].mean():.4f}",
        "",
        "（注：可在脚本顶部调整阈值以适配你的数据特性）"
    ]
    fname = f"{REPORT_PREFIX}_{timestamp_str}.txt"
    with open(fname, 'w', encoding='utf-8') as f:
        f.write("\n".join(report_content))
    print(f"✅ 报告已保存到: {fname}")

    # 8) 生成图表
    draw_beautiful_chart(
        stable_count, mono_inc_count, mono_dec_count, sudden_count, total_cves
    )


if __name__ == '__main__':
    main()
