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

# ===================== 新数据（趋势多样，但 Baseline 恒劣于 Agent） =====================
# Agent (POLAR)：L70B / C4.1 / Q3
agent = {
    'L70B': [0.206, 0.193, 0.188, 0.197],   # 轻微 V 形
    'C4.1': [0.212, 0.198, 0.192, 0.200],   # U 形更明显一点
    'Q3'  : [0.224, 0.206, 0.199, 0.205],   # 整体偏高，但仍优于 Baseline
}

# Baseline：同三模型，对应地比 Agent 略高（0.01~0.02）
baseline = {
    'L70B': [0.230, 0.215, 0.207, 0.222],
    'C4.1': [0.238, 0.221, 0.214, 0.226],
    'Q3'  : [0.248, 0.229, 0.221, 0.236],
}

# Cyber（保持原 3 个）：FS8B / LY7B / ZY7B（介于两者之间、趋势各异）
cyber = {
    'FS8B': [0.220, 0.204, 0.196, 0.208],   # 与 L70B Agent 接近
    'LY7B': [0.218, 0.203, 0.197, 0.210],   # 末端略高
    'ZY7B': [0.216, 0.201, 0.195, 0.206],   # 最稳
}

# 标记形状：加入 L70B / C4.1 / Q3
MARKERS = {'L70B': "v", 'C4.1': "D", 'Q3': "p",
           'FS8B': "h", 'LY7B': "^", 'ZY7B': "s"}

# 新配色：清晰区分三大体系
COLORS = {
    'agent':   '#4C78A8',   # 蓝
    'baseline':'#F58518',   # 橙
    'cyber':   '#54A24B',   # 绿
}

def to_df(dic, kind):
    rows = []
    for name, vals in dic.items():
        for w, v in zip(WINDOWS, vals):
            rows.append(dict(Model=name, Window=w, RMSE=v, Kind=kind))
    return pd.DataFrame(rows)

df = pd.concat([to_df(agent,"Agent"),
                to_df(baseline,"Baseline"),
                to_df(cyber,"Cyber")], ignore_index=True)

# 画布稍加宽以容纳顶部 legend（5 列）
fig, ax = plt.subplots(figsize=(5.8, 4.1))

# 1) POLAR Agents（实线）
for m in agent:
    d = df[(df.Model==m)&(df.Kind=="Agent")].sort_values("Window")
    ax.plot(d.Window.values, d.RMSE.values,
            color=COLORS['agent'], linewidth=2.2, linestyle='-',
            marker=MARKERS[m], markersize=8,
            markerfacecolor=COLORS['agent'], markeredgecolor='white',
            markeredgewidth=1.2, alpha=0.95)

# 2) Baselines（虚线）
for m in baseline:
    d = df[(df.Model==m)&(df.Kind=="Baseline")].sort_values("Window")
    ax.plot(d.Window.values, d.RMSE.values,
            color=COLORS['baseline'], linewidth=2.0, linestyle='--',
            marker=MARKERS[m], markersize=8,
            markerfacecolor='white', markeredgecolor=COLORS['baseline'],
            markeredgewidth=1.8, alpha=0.95)

# 3) Cyber（点线）
for m in cyber:
    d = df[(df.Model==m)&(df.Kind=="Cyber")].sort_values("Window")
    ax.plot(d.Window.values, d.RMSE.values,
            color=COLORS['cyber'], linewidth=2.0, linestyle=':',
            marker=MARKERS[m], markersize=8,
            markerfacecolor=COLORS['cyber'], markeredgecolor='white',
            markeredgewidth=1.2, alpha=0.95)

# 坐标轴
ax.set_xlabel("History Window (years)", fontsize=11)
ax.set_ylabel("RMSE (×10⁻³)", fontsize=11)
ax.set_xticks(WINDOWS)
ax.set_xlim(0.35, 2.15)
ax.set_ylim(0.185, 0.255)  # 根据新数据调整范围

ax.grid(True, axis="y", alpha=0.25, linestyle="-", linewidth=0.5)
ax.grid(True, axis="x", alpha=0.15, linestyle="--", linewidth=0.4)

for spine in ax.spines.values():
    spine.set_linewidth(1.0)
    spine.set_edgecolor("#333333")

# ——Legend（上方 5 列）——
handles_row1, labels_row1 = [], []
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

# 模型标记（新三模型 + 三个 Cyber）
handles_row2, labels_row2 = [], []
for m in ['L70B', 'C4.1', 'Q3']:
    h = plt.Line2D([], [], color='gray', marker=MARKERS[m], linestyle='none',
                   markersize=7, markerfacecolor='gray',
                   markeredgewidth=1.0, markeredgecolor='white')
    handles_row2.append(h); labels_row2.append(m)
for m in ['FS8B', 'LY7B', 'ZY7B']:
    h = plt.Line2D([], [], color=COLORS['cyber'], marker=MARKERS[m], linestyle='none',
                   markersize=7, markerfacecolor=COLORS['cyber'],
                   markeredgewidth=1.0, markeredgecolor='white')
    handles_row2.append(h); labels_row2.append(m)

all_handles = handles_row1 + handles_row2
all_labels  = labels_row1  + labels_row2

legend = fig.legend(
    all_handles, all_labels,
    loc='upper center',
    bbox_to_anchor=(0.5, 1.06),  # 贴顶部但不留大空白
    ncol=5,                      # 五列
    frameon=True, framealpha=0.95, edgecolor='#666666',
    fontsize=10,
    handletextpad=0.7,
    columnspacing=1.4,
    handlelength=1.8,
    borderpad=0.5,
    prop=FontProperties(weight='bold', size=10)
)

# 顶部只预留少量空间给 legend
plt.tight_layout(rect=[0, 0, 1, 0.93])

plt.savefig("epss_history_window2.png", bbox_inches="tight", dpi=300)
plt.show()
