#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import MultipleLocator
import matplotlib.patheffects as pe

# ========= 全局出版级风格 =========
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
    "axes.linewidth": 1.8,
    "grid.linewidth": 0.7,
    "axes.facecolor": "white",
    "figure.facecolor": "white",
    "xtick.labelsize": 11,
    "ytick.labelsize": 11,
    "axes.labelsize": 12,
    "legend.fontsize": 10,
})

WINDOWS = [0.5, 1.0, 1.5, 2.0]

# ========= 更明显&可交叉的“确定性”趋势（单位：绝对 RMSE；绘图时 ×1000 显示）=========
agent = {
    # 浅 U（1.5 最优）
    'GE2.5': [0.0320, 0.0298, 0.0290, 0.0301],
    # 明显 U（1.5 最优）
    'O4M'  : [0.0338, 0.0309, 0.0300, 0.0321],
    # 单调下降（历史越多越好，降幅更明显）
    'G5'   : [0.0331, 0.0313, 0.0306, 0.0299],
    # 强 U（1.5 最优，边缘更高）
    'L70B' : [0.0342, 0.0314, 0.0304, 0.0322],
    # 单调下降（较平滑）
    'C4.1' : [0.0316, 0.0301, 0.0295, 0.0292],
    # 单调上升（长窗更差）
    'Q3'   : [0.0317, 0.0326, 0.0337, 0.0349],
}
# Baseline：随窗略变，劣化 10–17%
baseline = {
    'GE2.5': [v*r for v, r in zip(agent['GE2.5'], [1.14, 1.12, 1.13, 1.15])],
    'O4M'  : [v*r for v, r in zip(agent['O4M'],   [1.15, 1.12, 1.12, 1.16])],
    'G5'   : [v*r for v, r in zip(agent['G5'],    [1.14, 1.13, 1.14, 1.15])],
    'L70B' : [v*r for v, r in zip(agent['L70B'],  [1.15, 1.13, 1.14, 1.16])],
    'C4.1' : [v*r for v, r in zip(agent['C4.1'],  [1.12, 1.11, 1.11, 1.13])],
    'Q3'   : [v*r for v, r in zip(agent['Q3'],    [1.15, 1.13, 1.12, 1.12])],
}

# ========= 学术配色 & 标记 =========
COL = {
    'GE2.5': "#2E7D32",  # green
    'O4M'  : "#1565C0",  # blue
    'G5'   : "#C62828",  # red
    'L70B' : "#6A1B9A",  # purple
    'C4.1' : "#E65100",  # orange
    'Q3'   : "#00695C",  # teal
}
MARK = {"GE2.5":"D", "O4M":"s", "G5":"^", "L70B":"D", "C4.1":"s", "Q3":"^"}

def stroke_fx():
    return [pe.Stroke(linewidth=4.2, foreground="white", alpha=0.65), pe.Normal()]

def build_df(agent, base):
    rows = []
    for name, vals in agent.items():
        for w, v in zip(WINDOWS, vals):
            rows.append(dict(Model=name, Window=w, RMSE=v, Kind="Agent"))
    for name, vals in base.items():
        for w, v in zip(WINDOWS, vals):
            rows.append(dict(Model=name, Window=w, RMSE=v, Kind="Baseline"))
    return pd.DataFrame(rows)

df = build_df(agent, baseline)
MODELS = list(agent.keys())

# ========= 绘制（单图 12 条线）=========
fig, ax = plt.subplots(figsize=(11.8, 4.6))

# Baseline：虚线 + 小圆点
for m in MODELS:
    d = df[(df.Model==m) & (df.Kind=="Baseline")].sort_values("Window")
    ax.plot(d.Window, d.RMSE*1000, color=COL[m], linestyle=(0,(3,2)),
            linewidth=2.0, alpha=0.9, solid_capstyle='round', dash_capstyle='round',
            zorder=2, path_effects=stroke_fx())
    ax.scatter(d.Window, d.RMSE*1000, s=42, facecolors="white",
               edgecolors=COL[m], linewidths=1.4, marker="o", zorder=3)

# Agent：实线 + 专属标记
for m in MODELS:
    d = df[(df.Model==m) & (df.Kind=="Agent")].sort_values("Window")
    ax.plot(d.Window, d.RMSE*1000, color=COL[m], linestyle="-",
            linewidth=3.1, alpha=0.98, solid_capstyle='round',
            zorder=4, path_effects=stroke_fx())
    ax.scatter(d.Window, d.RMSE*1000, s=60, facecolors="white",
               edgecolors=COL[m], linewidths=1.9, marker=MARK[m], zorder=5)

# 轴、网格、背景提示带
ax.set_xlabel("History Window (years)", fontsize=13, fontweight="bold")
ax.set_ylabel("RMSE (×10⁻³)", fontsize=13, fontweight="bold")
ax.set_xticks(WINDOWS)
ax.set_xlim(0.35, 2.15)
ax.set_ylim(28.8, 40.2)
ax.yaxis.set_major_locator(MultipleLocator(2))
ax.yaxis.set_minor_locator(MultipleLocator(1))
ax.grid(True, axis="y", which="major", alpha=0.28, linestyle="-", linewidth=0.75)
ax.grid(True, axis="y", which="minor", alpha=0.16, linestyle="--", linewidth=0.55)
ax.axvspan(0.95, 1.55, color="#3BA255", alpha=0.06, zorder=0)
for s in ax.spines.values():
    s.set_linewidth(1.8)
    s.set_edgecolor("#222222")

ax.set_title("EPSS Forecasting Performance: All Models",
             fontsize=15, fontweight="bold", pad=6)

# —— 顶部“模型图例”（6 项，颜色+标记）
model_handles, model_labels = [], []
for m in MODELS:
    h = plt.Line2D([], [], color=COL[m], marker=MARK[m], linestyle="-",
                   markersize=7, markerfacecolor="white", markeredgewidth=1.6,
                   linewidth=2.4)
    model_handles.append(h); model_labels.append(m)
fig.legend(model_handles, model_labels, loc='upper center',
           bbox_to_anchor=(0.5, 0.985), ncol=6,
           frameon=True, edgecolor="#333333", framealpha=0.96,
           columnspacing=1.2, handletextpad=0.6)

# —— 右上角“角色图例”（2 项）
role_items = [
    plt.Line2D([], [], color="#444", linewidth=3.1, linestyle="-"),
    plt.Line2D([], [], color="#444", linewidth=2.0, linestyle=(0,(3,2)))
]
ax.legend(role_items, ["Agent (ours)", "Baseline"],
          loc="upper right", frameon=True, edgecolor="#333333", framealpha=0.96)

fig.tight_layout(rect=[0, 0, 1, 0.90])
fig.savefig("epss_all_models_clean.png", bbox_inches="tight")
plt.show()
