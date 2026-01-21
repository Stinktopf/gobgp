#!/usr/bin/env python3
import os
import json
import numpy as np
import matplotlib.pyplot as plt
from glob import glob
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from matplotlib.ticker import MaxNLocator

# ============================================================
# CONFIG
# ============================================================

MODE_COLORS = {
    "oBGP": "#f15bb5",
    "BGP": "#00f5d4",
}

BASE_TO_TOPO = {
    "experiments-germany": "Germany50",
    "experiments-bad_gadget": "BadGadget",
    "experiments-noble-eu": "NobleEU",
}

bases = list(BASE_TO_TOPO.keys())

# Columns: Fill | Partial Drain | Full Drain
groups = [
    (7, 8, 9),   # Fill
    (4, 5, 6),   # Partial Drain
    (1, 2, 3),   # Full Drain
]
group_titles = ["Fill", "Partial Drain", "Full Drain"]

# One label per column (shown once at the top)
COLUMN_LABELS = [
    ["30 prefixes", "60 prefixes", "90 prefixes"],  # Fill
    ["25 %", "50 %", "75 %"],                       # Partial Drain
    ["30 prefixes", "60 prefixes", "90 prefixes"],  # Full Drain
]

# Metrics (path length merged)
metrics = [
    ("num_paths", "Number of Routes"),
    ("num_destinations", "Number of Prefixes"),
    ("path_len_merged", "Path Length"),
]

# ============================================================
# HELPERS
# ============================================================

def load_summary(filename):
    with open(filename, "r") as f:
        return json.load(f)

def extract_series(data, field):
    per_pod = data.get("per_pod_series", {})
    all_indices = {}

    for idxmap in per_pod.values():
        for idx, m in idxmap.items():
            idx = int(idx)
            if field not in m:
                continue
            vals = m[field]
            all_indices.setdefault(idx, {"min": [], "max": [], "avg": []})
            for k in ("min", "max", "avg"):
                if k in vals:
                    all_indices[idx][k].append(vals[k])

    series = {
        "mean_min": [], "mean_max": [], "avg": [],
        "global_min": [], "global_max": []
    }

    for idx in sorted(all_indices):
        mins = all_indices[idx]["min"]
        maxs = all_indices[idx]["max"]
        avgs = all_indices[idx]["avg"]

        series["mean_min"].append(np.mean(mins) if mins else np.nan)
        series["mean_max"].append(np.mean(maxs) if maxs else np.nan)
        series["avg"].append(np.mean(avgs) if avgs else np.nan)
        series["global_min"].append(np.min(mins) if mins else np.nan)
        series["global_max"].append(np.max(maxs) if maxs else np.nan)

    return series

def plot_regular(ax, series, color):
    x = np.arange(len(series["avg"]))
    ax.plot(x, series["avg"], color=color, lw=1.2)
    ax.fill_between(x, series["global_min"], series["global_max"],
                    color=color, alpha=0.06)
    ax.fill_between(x, series["mean_min"], series["mean_max"],
                    color=color, alpha=0.20)

def plot_pathlen_merged(ax, smin, savg, smax, color):
    x = np.arange(len(savg["avg"]))
    ax.fill_between(x, smin["global_min"], smax["global_max"],
                    color=color, alpha=0.06)
    ax.fill_between(x, smin["avg"], smax["avg"],
                    color=color, alpha=0.20)
    ax.plot(x, savg["avg"], color=color, lw=1.2)

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    n_topos = len(bases)
    n_groups = len(groups)
    n_metrics = len(metrics)

    fig, axes = plt.subplots(
        n_topos * n_metrics,
        n_groups * 3,
        figsize=(18, 20),
        sharex="col"
    )

    # --------------------------------------------------------
    # LOAD ALL DATA
    # --------------------------------------------------------
    cache = {}

    for topo_idx, base in enumerate(bases):
        for group in groups:
            for seq in group:
                for mode in ("BGP", "oBGP"):
                    pattern = os.path.join(
                        base,
                        f"{mode.lower()}-seq{seq}-*",
                        f"summary_{mode.lower()}.json"
                    )
                    files = sorted(glob(pattern))
                    if not files:
                        continue
                    data = load_summary(files[0])

                    for field, _ in metrics:
                        if field != "path_len_merged":
                            cache[(topo_idx, seq, mode, field)] = extract_series(data, field)

                    for f in ("path_len_min", "path_len_avg", "path_len_max"):
                        cache[(topo_idx, seq, mode, f)] = extract_series(data, f)

    # --------------------------------------------------------
    # COMPUTE Y-LIMITS PER ROW (topology × metric)
    # --------------------------------------------------------
    row_ylims = {}

    for topo_idx in range(n_topos):
        for metric_idx, (field, _) in enumerate(metrics):
            ymin, ymax = None, None

            for group in groups:
                for seq in group:
                    for mode in ("BGP", "oBGP"):
                        if field == "path_len_merged":
                            smin = cache.get((topo_idx, seq, mode, "path_len_min"))
                            smax = cache.get((topo_idx, seq, mode, "path_len_max"))
                            if smin is None or smax is None:
                                continue
                            vals = smin["global_min"] + smax["global_max"]
                        else:
                            s = cache.get((topo_idx, seq, mode, field))
                            if s is None:
                                continue
                            vals = (
                                s["global_min"] +
                                s["global_max"] +
                                s["mean_min"] +
                                s["mean_max"]
                            )

                        for v in vals:
                            if np.isnan(v):
                                continue
                            ymin = v if ymin is None else min(ymin, v)
                            ymax = v if ymax is None else max(ymax, v)

            if ymin is None or ymax is None:
                row_ylims[(topo_idx, metric_idx)] = (0, 1)
            else:
                d = ymax - ymin
                row_ylims[(topo_idx, metric_idx)] = (
                    ymin - 0.05 * d,
                    ymax + 0.05 * d
                )

    # --------------------------------------------------------
    # PLOT
    # --------------------------------------------------------
    for topo_idx, base in enumerate(bases):
        for group_idx, group in enumerate(groups):
            for c, seq in enumerate(group):
                col = group_idx * 3 + c

                for r, (field, ylabel) in enumerate(metrics):
                    row = topo_idx * n_metrics + r
                    ax = axes[row, col]

                    if field == "path_len_merged":
                        plot_pathlen_merged(
                            ax,
                            cache[(topo_idx, seq, "BGP", "path_len_min")],
                            cache[(topo_idx, seq, "BGP", "path_len_avg")],
                            cache[(topo_idx, seq, "BGP", "path_len_max")],
                            MODE_COLORS["BGP"],
                        )
                        plot_pathlen_merged(
                            ax,
                            cache[(topo_idx, seq, "oBGP", "path_len_min")],
                            cache[(topo_idx, seq, "oBGP", "path_len_avg")],
                            cache[(topo_idx, seq, "oBGP", "path_len_max")],
                            MODE_COLORS["oBGP"],
                        )
                    else:
                        plot_regular(ax, cache[(topo_idx, seq, "BGP", field)], MODE_COLORS["BGP"])
                        plot_regular(ax, cache[(topo_idx, seq, "oBGP", field)], MODE_COLORS["oBGP"])

                    ax.set_ylim(*row_ylims[(topo_idx, r)])
                    ax.grid(True, alpha=0.15)
                    ax.xaxis.set_major_locator(MaxNLocator(3))
                    ax.yaxis.set_major_locator(MaxNLocator(3))
                    ax.tick_params(labelsize=7)

                    # Y-label only once per row
                    if col == 0:
                        ax.set_ylabel(ylabel, fontsize=9)
                    else:
                        ax.set_ylabel("")
                        ax.tick_params(labelleft=False)

                    if row == n_topos * n_metrics - 1:
                        ax.set_xlabel("Time (s)", fontsize=9)

    # --------------------------------------------------------
    # LAYOUT FIRST (more top space for 2 header rows)
    # --------------------------------------------------------
    plt.tight_layout(rect=[0.08, 0.06, 1, 0.90])

    # --------------------------------------------------------
    # HEADERS (AFTER tight_layout! -> perfectly centered)
    # --------------------------------------------------------
    top_y = max(axes[0, c].get_position().y1 for c in range(n_groups * 3))

    # Two rows above plots
    y_group = min(0.995, top_y + 0.045)  # Fill / Partial Drain / Full Drain
    y_sub   = min(0.985, top_y + 0.020)  # 30/60/90 prefixes / 25/50/75 %

    for group_idx, title in enumerate(group_titles):
        start_col = group_idx * 3
        end_col = start_col + 2

        pos_l = axes[0, start_col].get_position()
        pos_r = axes[0, end_col].get_position()
        center_x = 0.5 * (pos_l.x0 + pos_r.x1)

        # Group title centered across its 3 columns
        fig.text(
            center_x, y_group, title,
            ha="center", va="top",
            fontsize=14, weight="bold"
        )

        # One sub-label per column
        for c in range(3):
            col = start_col + c
            pos = axes[0, col].get_position()
            cx = 0.5 * (pos.x0 + pos.x1)

            fig.text(
                cx, y_sub, COLUMN_LABELS[group_idx][c],
                ha="center", va="top",
                fontsize=11
            )

    # --------------------------------------------------------
    # TOPOLOGY LABELS (AFTER tight_layout!)
    # --------------------------------------------------------
    for topo_idx, base in enumerate(bases):
        first_row = topo_idx * n_metrics
        last_row = first_row + n_metrics - 1

        ax_top = axes[first_row, 0].get_position()
        ax_bottom = axes[last_row, 0].get_position()
        center_y = 0.5 * (ax_top.y1 + ax_bottom.y0)

        fig.text(
            0.035,
            center_y,
            BASE_TO_TOPO[base],
            rotation=90,
            va="center",
            ha="center",
            fontsize=14,
            weight="bold"
        )

    # --------------------------------------------------------
    # GLOBAL LEGEND
    # --------------------------------------------------------
    fig.legend(
        handles=[
            Line2D([0], [0], color=MODE_COLORS["BGP"], lw=1.4, label="BGP Average"),
            Line2D([0], [0], color=MODE_COLORS["oBGP"], lw=1.4, label="oBGP Average"),
            Patch(facecolor="0.5", alpha=0.20, label="Mean Min/Max"),
            Patch(facecolor="0.5", alpha=0.06, label="Global Min/Max"),
        ],
        loc="lower center",
        ncol=4,
        fontsize=10,
        frameon=False,
        bbox_to_anchor=(0.5, 0.015),
    )

    plt.show()
