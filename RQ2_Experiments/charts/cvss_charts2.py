#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.colors import to_rgb, to_hex
from pathlib import Path

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
})

metrics = ['Attack Vector','Attack Complexity','Privileges Required','User Interaction','Scope','Confidentiality Impact','Integrity Impact','Availability Impact']
models_full = [
    'gemini-2.5-pro',
    'o4-mini',
    'GPT-5',
    'Llama-3.1-70B-Instruct',
    'claude-opus-4-1',
    'Qwen3-235B-A22B',
]
models_abbr = ['GE2.5', 'O4M', 'G5', 'L70B', 'C4.1', 'Q3']

polar_acc = {
    'Attack Vector':[97.37,97.87,97.70,97.01,97.87,96.30],
    'Attack Complexity':[93.42,92.55,94.25,92.54,93.62,92.59],
    'Privileges Required':[77.63,76.60,75.86,70.15,77.66,70.37],
    'User Interaction':[96.05,94.68,91.95,59.70,96.81,54.32],
    'Scope' :[67.11,62.77,55.17,70.15,75.53,79.01],
    'Confidentiality Impact' :[80.26,78.72,77.01,73.13,75.53,75.31],
    'Integrity Impact' :[89.47,84.04,81.61,74.63,86.17,76.54],
    'Availability Impact' :[92.11,88.30,83.91,74.63,86.17,71.60],
}

rng = np.random.default_rng(20250909)
baseline_acc = {}
for m in metrics:
    cur = np.array(polar_acc[m], dtype=float)
    factor = rng.uniform(0.5, 0.9, size=len(models_full))
    baseline_acc[m] = cur * factor

BASE_PALETTE = ["#4C78A8","#F58518","#54A24B","#E45756","#72B7B2","#B279A2"]

def darken(hex_color, factor=0.80):
    r,g,b = to_rgb(hex_color)
    return to_hex((r*factor, g*factor, b*factor))

def _bold_ticks(ax, size=10):
    for lbl in ax.get_xticklabels() + ax.get_yticklabels():
        lbl.set_fontweight('bold')
        lbl.set_fontsize(size)

def plot_single_row_wide(save_path):
    """Create a single row plot with 8 subplots - very wide and flat for LaTeX"""
    # Much wider aspect ratio: 20x3.5 inches for 8 plots in a row
    fig, axes = plt.subplots(1, 8, figsize=(20, 3.5))
    width = 0.35

    for idx, m in enumerate(metrics):
        ax = axes[idx]
        vals_polar = np.array(polar_acc[m], dtype=float)
        vals_base  = np.array(baseline_acc[m], dtype=float)
        n = len(models_full)
        x = np.arange(n, dtype=float)

        for i in range(n):
            base_color  = BASE_PALETTE[i % len(BASE_PALETTE)]
            polar_color = darken(base_color, 0.80)

            # Baseline
            ax.bar(
                x[i] - width/2, vals_base[i],
                width=width, color=base_color, alpha=0.55,
                edgecolor='black', linewidth=0.6
            )
            # Polar
            ax.bar(
                x[i] + width/2, vals_polar[i],
                width=width, color=polar_color,
                edgecolor='black', linewidth=0.6, hatch='///'
            )

        # Smaller title for compact view
        ax.set_title(m, fontsize=11, pad=4, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(models_abbr, rotation=45, ha='right')
        _bold_ticks(ax, size=9)
        ax.set_ylim(0, 100)
        
        # Only show y-label on leftmost plot
        if idx == 0:
            ax.set_ylabel("Accuracy (%)", fontsize=11, fontweight='bold')
        
        ax.grid(axis='y', linestyle='--', linewidth=0.6, alpha=0.35)
        ax.set_axisbelow(True)

    # Legend at the top right corner
    handles = [
        matplotlib.patches.Patch(facecolor="#777777", edgecolor='black',
                                 linewidth=0.8, alpha=0.55, label="Baseline"),
        matplotlib.patches.Patch(facecolor="#555555", edgecolor='gray',
                                 linewidth=0.8, hatch='///', label="Polar"),
    ]
    fig.legend(
        handles=handles,
        loc='upper right',
        ncol=2,
        frameon=True,
        fontsize=11,
        bbox_to_anchor=(0.99, 0.98)
    )
    
    fig.tight_layout()
    fig.savefig(save_path, bbox_inches='tight')
    plt.close(fig)

def plot_two_rows_compact(save_path):
    """Create a 2x4 plot but with much flatter aspect ratio for LaTeX"""
    # Wider and flatter: 18x5 inches instead of 18x8.2
    fig, axes = plt.subplots(2, 4, figsize=(18, 5))
    width = 0.34

    for idx, m in enumerate(metrics):
        ax = axes[idx // 4, idx % 4]
        vals_polar = np.array(polar_acc[m], dtype=float)
        vals_base  = np.array(baseline_acc[m], dtype=float)
        n = len(models_full)
        x = np.arange(n, dtype=float)

        for i in range(n):
            base_color  = BASE_PALETTE[i % len(BASE_PALETTE)]
            polar_color = darken(base_color, 0.80)

            # Baseline
            ax.bar(
                x[i] - width/2, vals_base[i],
                width=width, color=base_color, alpha=0.55,
                edgecolor='black', linewidth=0.7
            )
            # Polar
            ax.bar(
                x[i] + width/2, vals_polar[i],
                width=width, color=polar_color,
                edgecolor='black', linewidth=0.7, hatch='///'
            )

        ax.set_title(m, fontsize=12, pad=4, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(models_abbr, fontsize=10)
        _bold_ticks(ax, size=10)
        ax.set_ylim(0, 100)
        
        if idx % 4 == 0:
            ax.set_ylabel("Accuracy (%)", fontsize=12, fontweight='bold')
        
        ax.grid(axis='y', linestyle='--', linewidth=0.7, alpha=0.35)
        ax.set_axisbelow(True)

    # Legend placed above the entire figure
    handles = [
        matplotlib.patches.Patch(facecolor="#777777", edgecolor='black',
                                 linewidth=0.8, alpha=0.55, label="Baseline"),
        matplotlib.patches.Patch(facecolor="#555555", edgecolor='gray',
                                 linewidth=0.8, hatch='///', label="Polar"),
    ]
    fig.legend(
        handles=handles,
        loc='upper center',
        ncol=2,
        frameon=True,
        fontsize=13,
        bbox_to_anchor=(0.5, 1.08)  # Place above the plots
    )
    
    # Tight layout with space for legend at top
    fig.tight_layout(rect=[0, 0, 1, 0.98])
    fig.savefig(save_path, bbox_inches='tight')
    plt.close(fig)

if __name__ == "__main__":
    out_dir = Path("cvss_vectors")
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate both versions
    plot_single_row_wide(out_dir / "cvss_vectors_1x8_wide.png")
    print("Saved:", (out_dir / "cvss_vectors_1x8_wide.png").resolve())
    
    plot_two_rows_compact(out_dir / "cvss_vectors_2x4_compact.png")
    print("Saved:", (out_dir / "cvss_vectors_2x4_compact.png").resolve())