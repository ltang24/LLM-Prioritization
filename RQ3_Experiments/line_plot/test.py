#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import MultipleLocator
from matplotlib.font_manager import FontProperties

plt.rcParams.update({
    "figure.dpi": 170,
    "savefig.dpi": 340,
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "Nimbus Roman", "DejaVu Serif"],
    "mathtext.fontset": "cm",
    "text.color": "#111111",
    "axes.edgecolor": "#222222",
    "axes.labelcolor": "#111111",
    "xtick.color": "#222222",
    "ytick.color": "#222222",
    "axes.linewidth": 1.2,
    "grid.linewidth": 0.6,
    "axes.facecolor": "white",
    "figure.facecolor": "white",
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "axes.labelsize": 11,
    "legend.fontsize": 9,
})

WINDOWS = [0.5, 1.0, 1.5, 2.0]

# Data aligned with stable trend RMSE values from your table
agent = {
    'GE2.5': [0.198, 0.178, 0.172, 0.185],
    'O4M'  : [0.216, 0.196, 0.189, 0.203],
    'G5'   : [0.221, 0.201, 0.194, 0.208],
}

# Baseline without POLAR (higher values)
baseline = {
    'GE2.5': [0.235, 0.214, 0.208, 0.223],
    'O4M'  : [0.248, 0.228, 0.221, 0.237],
    'G5'   : [0.254, 0.234, 0.227, 0.243],
}

# Cyber agents (between baseline and POLAR)
cyber = {
    'FS8B': [0.225, 0.205, 0.199, 0.212],
    'LY7B': [0.222, 0.202, 0.196, 0.209],
    'ZY7B': [0.219, 0.199, 0.193, 0.206],
}

MARKERS = {'GE2.5': "o", 'O4M': "s", 'G5': "^", 
           'FS8B': "D", 'LY7B': "v", 'ZY7B': "p"}

# Lighter colors (no gradient needed)
COLORS = {
    'agent': '#5B9BD5',      # Light blue
    'baseline': '#F4B183',   # Light orange
    'cyber': '#B4A7D6'       # Light purple
}

def to_df(dic, kind):
    rows = []
    for name, vals in dic.items():
        for w, v in zip(WINDOWS, vals):
            rows.append(dict(Model=name, Window=w, RMSE=v, Kind=kind))
    return pd.DataFrame(rows)

df = pd.concat([to_df(agent,"Agent"), to_df(baseline,"Baseline"), 
                to_df(cyber,"Cyber")], ignore_index=True)

# Adjust figure size to accommodate legend on top
fig, ax = plt.subplots(figsize=(5.6, 4.2))

# 1) POLAR Agents (solid line)
for m in agent:
    d = df[(df.Model==m)&(df.Kind=="Agent")].sort_values("Window")
    x = d.Window.values
    y = d.RMSE.values
    ax.plot(x, y, color=COLORS['agent'], linewidth=2.2, linestyle='-', 
            marker=MARKERS[m], markersize=8, markerfacecolor=COLORS['agent'],
            markeredgecolor='white', markeredgewidth=1.2, alpha=0.9)

# 2) Baselines (dashed line)
for m in baseline:
    d = df[(df.Model==m)&(df.Kind=="Baseline")].sort_values("Window")
    x = d.Window.values
    y = d.RMSE.values
    ax.plot(x, y, color=COLORS['baseline'], linewidth=2.0, linestyle='--',
            marker=MARKERS[m], markersize=8, markerfacecolor='white',
            markeredgecolor=COLORS['baseline'], markeredgewidth=1.8, alpha=0.9)

# 3) Cyber agents (dotted line)
for m in cyber:
    d = df[(df.Model==m)&(df.Kind=="Cyber")].sort_values("Window")
    x = d.Window.values
    y = d.RMSE.values
    ax.plot(x, y, color=COLORS['cyber'], linewidth=2.0, linestyle=':',
            marker=MARKERS[m], markersize=8, markerfacecolor=COLORS['cyber'],
            markeredgecolor='white', markeredgewidth=1.2, alpha=0.9)

# Axes and grid
ax.set_xlabel("History Window (years)", fontsize=11)
ax.set_ylabel("RMSE (×10⁻³)", fontsize=11)
ax.set_xticks(WINDOWS)
ax.set_xlim(0.35, 2.15)
ax.set_ylim(0.165, 0.265)

# Grid
ax.grid(True, axis="y", alpha=0.25, linestyle="-", linewidth=0.5)
ax.grid(True, axis="x", alpha=0.15, linestyle="--", linewidth=0.4)

# Spines
for spine in ax.spines.values():
    spine.set_linewidth(1.0)
    spine.set_edgecolor("#333333")

# Create two separate legends for better control
# First row: System types (POLAR, Baseline, Cyber)
handles_row1 = []
labels_row1 = []

handles_row1.append(plt.Line2D([], [], color=COLORS['agent'], linewidth=2.2, linestyle='-',
                               marker='o', markersize=7, markerfacecolor=COLORS['agent'],
                               markeredgecolor='white', markeredgewidth=1.0))
labels_row1.append('POLAR')

handles_row1.append(plt.Line2D([], [], color=COLORS['baseline'], linewidth=2.0, linestyle='--',
                               marker='o', markersize=7, markerfacecolor='white',
                               markeredgecolor=COLORS['baseline'], markeredgewidth=1.5))
labels_row1.append('Baseline')

handles_row1.append(plt.Line2D([], [], color=COLORS['cyber'], linewidth=2.0, linestyle=':',
                               marker='o', markersize=7, markerfacecolor=COLORS['cyber'],
                               markeredgecolor='white', markeredgewidth=1.0))
labels_row1.append('Cyber')

# Second row: Model markers
handles_row2 = []
labels_row2 = []

for m in ['GE2.5', 'O4M', 'G5']:
    h = plt.Line2D([], [], color='gray', marker=MARKERS[m], linestyle='none',
                   markersize=7, markerfacecolor='gray',
                   markeredgewidth=1.0, markeredgecolor='white')
    handles_row2.append(h)
    labels_row2.append(m)

for m in ['FS8B', 'LY7B', 'ZY7B']:
    h = plt.Line2D([], [], color=COLORS['cyber'], marker=MARKERS[m], linestyle='none',
                   markersize=7, markerfacecolor=COLORS['cyber'],
                   markeredgewidth=1.0, markeredgecolor='white')
    handles_row2.append(h)
    labels_row2.append(m)

# Combine handles and labels with proper spacing
all_handles = handles_row1 + handles_row2
all_labels = labels_row1 + labels_row2

## ——把 ax.legend(...) 换成 fig.legend(...)，放到图外上方——
# 注意：ncol=6 让第二行的 6 个模型图例与第一行对齐
legend = fig.legend(
    all_handles, all_labels,
    loc='upper center',
    bbox_to_anchor=(0.5, 0.93),   # 顶部更贴边，避免留白
    ncol=5,                       # <<< 五列
    frameon=True, framealpha=0.95, edgecolor='#666666',
    fontsize=10,
    handletextpad=0.7,
    columnspacing=1.4,            # 列间距稍收紧
    handlelength=1.8,             # 线段长度略短一点
    borderpad=0.5,
    prop=FontProperties(weight='bold', size=10) 
)

# 给上方图例留空间（根据你的版面可微调 0.90~0.94）
plt.tight_layout(rect=[0, 0, 1, 0.93])

# 给上方的图例留出空间
plt.subplots_adjust(top=0.76)   # 比原来 0.82 再多留一点


plt.savefig("epss_history_window.png", bbox_inches="tight", dpi=300)
plt.show()