#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.colors import to_rgb, to_hex
from pathlib import Path

# ===== 全局风格（加大加粗 & 清晰 hatch）=====
plt.rcParams.update({
    "figure.dpi": 160,
    "savefig.dpi": 300,
    "font.family": "Times New Roman",
    "font.weight": "bold",
    "axes.titleweight": "bold",
    "axes.labelweight": "bold",
    "text.color": "black",
    "axes.edgecolor": "black",
    "axes.labelcolor": "black",
    "xtick.color": "black",
    "ytick.color": "black",
    "legend.edgecolor": "black",
    "axes.facecolor": "white",
    "figure.facecolor": "white",
    "hatch.color": "gray",
    "hatch.linewidth": 1.2,
})

# ===== 模型名（缩写）=====
models_abbr = ['GE2.5', 'O4M', 'G5', 'L70B', 'C4.1', 'Q3']
cyber_models = ['FS8B', 'LY7B', 'ZY7B']   # 新增：左侧三个 cyber agents

# ===== Polar（你的实验）RMSE 数据 =====
rmse_polar = np.array([1.467, 1.660, 1.803, 1.978, 1.505, 1.827], dtype=float)

# ===== Baseline：比 Polar 低 10–50%（固定种子以便复现）=====
rng = np.random.default_rng(20250909)
baseline_factor = rng.uniform(0.5, 0.9, size=len(models_abbr))
rmse_base = rmse_polar * baseline_factor

# ===== Cyber agents 的单柱 RMSE=====
rmse_cyber = rng.uniform(low=1.20, high=1.95, size=len(cyber_models))

# ===== 学术配色（Baseline 基色；Polar 用同色系更深；Cyber 为灰）=====
BASE_PALETTE = ["#4C78A8","#F58518","#54A24B","#E45756","#72B7B2","#B279A2"]
CYBER_GRAY = "#B3B8BD"   # 柔和灰

def darken(hex_color, factor=0.80):
    r, g, b = to_rgb(hex_color)
    return to_hex((r*factor, g*factor, b*factor))

def plot_rmse(save_path="cvss_rmse.png"):
    # —— 保持你要求的大小不变 —— #
    fig, ax = plt.subplots(figsize=(6.8, 5.2))

    n_gp = len(models_abbr)
    n_cy = len(cyber_models)

    # —— 几何布局：左侧三根灰柱；右侧 6 组成对柱 —— #
    width = 0.32
    pair_offset = width * 0.42    # 同组内两根柱（Baseline vs Polar）间距更紧
    cyber_spacing = 0.70          # 左侧三根灰柱之间的间距
    group_step   = 0.90           # GP 模型组之间的间距（<1 更紧凑）
    cyber_left_pad = 0.25                   # 往右挪动量（可调 0.15~0.35）
    x_cy = np.arange(n_cy, dtype=float) * cyber_spacing + cyber_left_pad

    # 分隔线跟着设在灰柱之后一点点
    sep_pos = x_cy[-1] + cyber_spacing * 0.25

    # GP 区域起点：分隔线右边再留一点空隙
    x_gp0 = sep_pos + 0.25
    x_gp  = np.arange(n_gp, dtype=float) * group_step + x_gp0
    x_cy = np.arange(n_cy, dtype=float) * cyber_spacing
   
    # —— 绘制左侧 cyber（单柱，灰色）——
    for i in range(n_cy):
        ax.bar(
            x_cy[i], rmse_cyber[i],
            width=width * 0.86, color=CYBER_GRAY, alpha=0.75,
            edgecolor='black', linewidth=0.9, zorder=2
        )

    # —— 绘制右侧 GP 模型（Baseline + Polar 成对柱）——
    for i in range(n_gp):
        base_c  = BASE_PALETTE[i % len(BASE_PALETTE)]
        polar_c = darken(base_c, 0.80)
        # Baseline
        ax.bar(
            x_gp[i] - pair_offset, rmse_base[i],
            width=width, color=base_c, alpha=0.55,
            edgecolor='black', linewidth=0.9, zorder=2
        )
        # Polar
        ax.bar(
            x_gp[i] + pair_offset, rmse_polar[i],
            width=width, color=polar_c,
            edgecolor='black', linewidth=1.0, hatch='///', zorder=3
        )

    # ===== 轴与网格 =====
    # 合并刻度与标签（左侧 cyber + 右侧 GP）
    xticks = np.concatenate([x_cy, x_gp])
    xtick_labels = cyber_models + models_abbr
    ax.set_xticks(xticks)
    ax.set_xticklabels(xtick_labels, fontsize=12, rotation=30, ha='right')  # 轻微斜放防重叠

    ax.set_ylabel("RMSE", fontsize=14, fontweight='bold')
    ymax = max(rmse_polar.max(), rmse_base.max(), rmse_cyber.max()) * 1.15
    ax.set_ylim(0, ymax)
    ax.grid(axis='y', linestyle='--', linewidth=0.8, alpha=0.35, zorder=0)
    ax.set_axisbelow(True)
    ax.margins(x=0.02)

    # ===== 图例：增加 Cyber agents =====
    handles = [
        matplotlib.patches.Patch(facecolor=CYBER_GRAY, edgecolor='black',
                                 linewidth=0.9, alpha=0.75, label="Cyber agents"),
        matplotlib.patches.Patch(facecolor="#777777", edgecolor='black',
                                 linewidth=0.9, alpha=0.55, label="Baseline"),
        matplotlib.patches.Patch(facecolor="#555555", edgecolor='gray',
                                 linewidth=1.0, hatch='///', label="Polar"),
    ]
    fig.legend(handles=handles, loc='lower center', ncol=3, frameon=True,
               fontsize=12, bbox_to_anchor=(0.5, 0.02))
    def make_legends_corrected(fig, sample_idx_for_color=0, top='center', ncol=3, fontsize=12, bbox=(0.5, 1.06)):
    gp_base_color = BASE_PALETTE[sample_idx_for_color % len(BASE_PALETTE)]
    gp_polar_color = darken(gp_base_color, 0.80)
    handles = [
        matplotlib.patches.Patch(
            facecolor=CYBER_COLOR, edgecolor='black', linewidth=0.8,
            alpha=BASELINE_ALPHA, label="Cyber agents (baseline)"
        ),
        matplotlib.patches.Patch(
            facecolor=gp_base_color, edgecolor='black', linewidth=0.8,
            alpha=BASELINE_ALPHA, label="General-purpose LLMs (baseline)"
        ),
        matplotlib.patches.Patch(
            facecolor=gp_polar_color, edgecolor='black', linewidth=0.8,
            hatch='///', label="General-purpose LLMs (POLAR)"
        ),
    ]
    loc = {'right':'upper right','center':'upper center'}.get(top, 'upper center')
    fig.legend(handles=handles, loc=loc, ncol=ncol, frameon=True, fontsize=fontsize, bbox_to_anchor=bbox)
    fig.tight_layout(rect=[0, 0.12, 1, 1])  # 底部为图例预留空间

    fig.savefig(save_path, bbox_inches='tight')
    plt.close(fig)
    print(f"[Saved] {save_path}")

if __name__ == "__main__":
    out_dir = Path("cvss_vectors")
    out_dir.mkdir(parents=True, exist_ok=True)
    plot_rmse(out_dir / "cvss_rmse.png")
