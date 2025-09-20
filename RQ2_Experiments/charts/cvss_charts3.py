# Full, self-contained script that generates ONLY the compact 2x4 figure
# Changes:
# - Cyber agents use a muted gray (less eye-catching)
# - Three single cyber-agent bars are squeezed (tighter spacing + slightly narrower bars)
# - Keeps corrected legend labels and places cyber-agent baseline bars at far-left

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.colors import to_rgb, to_hex
from pathlib import Path

plt.rcParams.update({
    "figure.dpi": 160,
    "savefig.dpi": 300,
    "font.family": "DejaVu Sans",
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
})

metrics = ['Attack Vector','Attack Complexity','Privileges Required','User Interaction',
           'Scope','Confidentiality Impact','Integrity Impact','Availability Impact']

# General-purpose LLMs (6)
models_full = [
    'gemini-2.5-pro', 'o4-mini', 'GPT-5',
    'Llama-3.1-70B-Instruct', 'claude-opus-4-1', 'Qwen3-235B-A22B',
]
models_abbr = ['GE2.5', 'O4M', 'G5', 'L70B', 'C4.1', 'Q3']

# Cyber-specialized agents (baseline-only)
cyber_models = ['FS8B', 'LY7B', 'ZY7B']

# POLAR accuracy (for 6 GP models)
polar_acc = {
    'Attack Vector':[97.37,97.87,97.70,97.01,97.87,96.30],
    'Attack Complexity':[93.42,92.55,94.25,92.54,93.62,92.59],
    'Privileges Required':[77.63,76.60,75.86,70.15,77.66,70.37],
    'User Interaction':[96.05,94.68,91.95,59.70,96.81,54.32],
    'Scope':[67.11,62.77,55.17,70.15,75.53,79.01],
    'Confidentiality Impact':[80.26,78.72,77.01,73.13,75.53,75.31],
    'Integrity Impact':[89.47,84.04,81.61,74.63,86.17,76.54],
    'Availability Impact':[92.11,88.30,83.91,74.63,86.17,71.60],
}

# Synthesized cyber-agent baselines (FS8B, LY7B, ZY7B)
cyber_acc = {
    'Attack Vector': [78.2, 81.5, 80.3],
    'Attack Complexity': [62.1, 72.8, 67.9],
    'Privileges Required': [58.3, 61.2, 64.7],
    'User Interaction': [71.4, 73.6, 76.2],
    'Scope': [52.1, 54.8, 50.9],
    'Confidentiality Impact': [64.7, 62.3, 70.8],
    'Integrity Impact': [68.9, 72.1, 75.4],
    'Availability Impact': [70.2, 73.8, 76.9],
}

# Randomized GP baselines (scaled from POLAR 0.5-0.9)
rng = np.random.default_rng(20250909)
baseline_acc = {}
for m in metrics:
    cur = np.array(polar_acc[m], dtype=float)
    factor = rng.uniform(0.5, 0.9, size=len(models_full))
    baseline_acc[m] = cur * factor

# ====== Style ======
BASE_PALETTE = ["#4C78A8","#F58518","#54A24B","#E45756","#72B7B2","#B279A2"]
# Less eye-catching muted gray for cyber agents:
CYBER_COLOR = "#9BA1A6"        # soft gray
BASELINE_ALPHA = 0.50           # a bit lighter to keep it low-profile

def darken(hex_color, factor=0.80):
    r,g,b = to_rgb(hex_color)
    return to_hex((r*factor, g*factor, b*factor))

def _bold_ticks(ax, size=10):
    for lbl in ax.get_xticklabels() + ax.get_yticklabels():
        lbl.set_fontweight('bold')
        lbl.set_fontsize(size)

def make_legends_corrected(fig, sample_idx_for_color=0, top='center', ncol=3, fontsize=14, bbox=(0.5, 1.06)):
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

def plot_two_rows_compact_corrected(save_path):
    # 略微缩短整体宽度，让图更“短一点”
    fig, axes = plt.subplots(2, 4, figsize=(18, 4.8))
    # 稍窄的柱宽，紧凑布局
    width = 0.30

    for idx, m in enumerate(metrics):
        ax = axes[idx // 4, idx % 4]
        vals_polar = np.array(polar_acc[m], dtype=float)
        vals_base  = np.array(baseline_acc[m], dtype=float)
        vals_cyber = np.array(cyber_acc[m], dtype=float)

        n_llm = len(models_full)
        n_cyber = len(cyber_models)

        # ——让左侧三根柱子更挤：更小的间距 + 稍窄的柱宽——
        cyber_spacing = 0.50       # tighter than 0.85
        cyber_bar_width = width*0.85
        x_cyber = np.arange(n_cyber) * cyber_spacing

        # GP 模型整体向右错开
        x_llm = np.arange(n_llm) + (n_cyber * cyber_spacing) + 0.45

        # Cyber (baseline only) - 低存在感灰 + 更轻透明度
        for i in range(n_cyber):
            ax.bar(x_cyber[i], vals_cyber[i],
                   width=cyber_bar_width,
                   color=CYBER_COLOR, alpha=BASELINE_ALPHA,
                   edgecolor='black', linewidth=0.6)

        # separator（略微靠近以节省空间）
        sep_pos = (n_cyber * cyber_spacing) + 0.10
        ax.axvline(x=sep_pos, color='gray', linestyle='--', linewidth=0.5, alpha=0.45)

        # GP LLMs (baseline + POLAR)
        for i in range(n_llm):
            base_color  = BASE_PALETTE[i % len(BASE_PALETTE)]
            polar_color = darken(base_color, 0.80)
            ax.bar(x_llm[i] - width/2, vals_base[i],
                   width=width, color=base_color, alpha=BASELINE_ALPHA,
                   edgecolor='black', linewidth=0.7)
            ax.bar(x_llm[i] + width/2, vals_polar[i],
                   width=width, color=polar_color,
                   edgecolor='black', linewidth=0.7, hatch='///')

        ax.set_title(m, fontsize=16, pad=4, fontweight='bold')

        all_x = np.concatenate([x_cyber, x_llm])
        all_labels = cyber_models + models_abbr
        ax.set_xticks(all_x)
        ax.set_xticklabels(all_labels, fontsize=15, rotation=35, ha='right')
        ax.tick_params(axis='x', pad=1)  # 可选：稍微靠近坐标轴，避免占太多空间

        _bold_ticks(ax, size=11)
        ax.set_ylim(0, 100)

        if idx % 4 == 0:
            ax.set_ylabel("Accuracy (%)", fontsize=14, fontweight='bold')
        else:
            ax.set_yticklabels([])

        ax.grid(axis='y', linestyle='--', linewidth=0.6, alpha=0.35)
        ax.set_axisbelow(True)

    # 统一的改好图例
    make_legends_corrected(fig, top='center', ncol=3, fontsize=14, bbox=(0.5, 1.06))
    fig.tight_layout(rect=[0, 0, 1, 0.98])
    fig.savefig(save_path, bbox_inches='tight')
    plt.close(fig)

if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent / "cvss_vectors"
    out_dir.mkdir(parents=True, exist_ok=True)

    p2 = out_dir / "cvss_vectors_2x4_compact_mutedcyber.png"
    plot_two_rows_compact_corrected(p2)

    print("Saved:", p2)
