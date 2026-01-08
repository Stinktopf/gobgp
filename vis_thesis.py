#!/usr/bin/env python3
import os
import json
import numpy as np
import matplotlib.pyplot as plt
from glob import glob
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from matplotlib.ticker import MaxNLocator

VIS_DIR = "vis"

MODE_COLORS = {
    "oBGP": "#f15bb5",
    "BGP": "#00f5d4",
}

def load_summary(filename):
    with open(filename, "r") as f:
        return json.load(f)

def extract_series(data, pod_filter=None, field="num_paths"):
    per_pod = data.get("per_pod_series", {})
    all_indices = {}
    for pod, idxmap in per_pod.items():
        if pod_filter and pod != pod_filter:
            continue
        for idx, metrics in idxmap.items():
            idx = int(idx)
            if field in metrics:
                vals = metrics[field]
                all_indices.setdefault(idx, {"min": [], "max": [], "avg": []})
                for k in ("min", "max", "avg"):
                    if k in vals:
                        all_indices[idx][k].append(vals[k])
    series = {
        "mean_min": [], "mean_max": [], "avg": [],
        "global_min": [], "global_max": []
    }
    for idx in sorted(all_indices.keys()):
        mins = all_indices[idx]["min"]
        maxs = all_indices[idx]["max"]
        avgs = all_indices[idx]["avg"]
        series["mean_min"].append(np.mean(mins) if mins else np.nan)
        series["mean_max"].append(np.mean(maxs) if maxs else np.nan)
        series["avg"].append(np.mean(avgs) if avgs else np.nan)
        series["global_min"].append(np.min(mins) if mins else np.nan)
        series["global_max"].append(np.max(maxs) if maxs else np.nan)
    return series

def get_series_range(series):
    vals = []
    for k in ("mean_min", "mean_max", "avg", "global_min", "global_max"):
        vals.extend([v for v in series[k] if not np.isnan(v)])
    if vals:
        return min(vals), max(vals)
    return None, None

def plot_min_max_avg_multi(ax, series, color, mode_label,
                           ylabel=None, ylim=None,
                           set_xlabel=False, set_ylabel=False):
    x = np.arange(len(series["avg"]))
    ax.plot(x, series["avg"], color=color, label=mode_label, linewidth=1.4)
    ax.fill_between(x, series["global_min"], series["global_max"], color=color, alpha=0.06)
    ax.fill_between(x, series["mean_min"], series["mean_max"], color=color, alpha=0.20)
    if set_xlabel:
        ax.set_xlabel("Time in Seconds", fontsize=9)
    if set_ylabel and ylabel is not None:
        ax.set_ylabel(ylabel, fontsize=9)
    if ylim:
        ax.set_ylim(*ylim)
    ax.grid(True, alpha=0.18, linewidth=0.6)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))

BASE_TO_TOPO = {
    "experiments-germany": "Germany50",
    "experiments-bad_gadget": "BadGadget",
    "experiments-noble-eu": "NobleEU",
}

bases = list(BASE_TO_TOPO.keys())

groups = [(1, 2, 3), (4, 5, 6), (7, 8, 9)]
group_names = ["Full Drain", "Partial Drain", "Fill"]

scenario_labels = {
    1: "Drain from 30 Prefixes",
    2: "Drain from 60 Prefixes",
    3: "Drain from 90 Prefixes",
    4: "25% Partial Drain",
    5: "50% Partial Drain",
    6: "75% Partial Drain",
    7: "Fill to 30 Prefixes",
    8: "Fill to 60 Prefixes",
    9: "Fill to 90 Prefixes",
}

metrics = [
    ("num_paths", "Number of Routes"),
    ("num_destinations", "Number of Prefixes"),
    ("path_len_min", "Minimum Path Length"),
    ("path_len_avg", "Average Path Length"),
    ("path_len_max", "Maximum Path Length"),
]

if __name__ == "__main__":
    for base in bases:
        topo = BASE_TO_TOPO.get(base, base)
        out_dir = os.path.join(VIS_DIR, topo)
        os.makedirs(out_dir, exist_ok=True)

        for g_idx, group in enumerate(groups, 1):
            series_cache = {}
            ylimits = {field: [None, None] for field, _ in metrics}

            for seq in group:
                for mode in ("BGP", "oBGP"):
                    pattern = os.path.join(
                        base,
                        f"{mode.lower()}-seq{seq}-*",
                        f"summary_{mode.lower()}.json",
                    )
                    files = sorted(glob(pattern))
                    if not files:
                        continue
                    data = load_summary(files[0])
                    for field, _ in metrics:
                        s = extract_series(data, field=field)
                        series_cache[(seq, mode, field)] = s
                        ymin, ymax = get_series_range(s)
                        if ymin is None or ymax is None:
                            continue
                        cur_min, cur_max = ylimits[field]
                        if cur_min is None or ymin < cur_min:
                            ylimits[field][0] = ymin
                        if cur_max is None or ymax > cur_max:
                            ylimits[field][1] = ymax

            for field in ylimits:
                ymin, ymax = ylimits[field]
                if ymin is None or ymax is None:
                    ylimits[field] = (0, 1)
                else:
                    d = ymax - ymin
                    margin = d * 0.05 if d > 0 else 1
                    ylimits[field] = (ymin - margin, ymax + margin)

            fig, axes = plt.subplots(
                5, 3, figsize=(10.5, 11.5),
                sharex=True, sharey="row"
            )

            for col, seq in enumerate(group):
                label = scenario_labels[seq]
                for row, (field, ylabel) in enumerate(metrics):
                    key_bgp = (seq, "BGP", field)
                    key_obgp = (seq, "oBGP", field)
                    if key_bgp not in series_cache or key_obgp not in series_cache:
                        continue
                    ax = axes[row, col]
                    plot_min_max_avg_multi(
                        ax,
                        series_cache[key_bgp],
                        MODE_COLORS["BGP"],
                        "BGP avg",
                        ylabel=ylabel if col == 0 else None,
                        ylim=ylimits[field],
                        set_xlabel=row == len(metrics) - 1,
                        set_ylabel=col == 0,
                    )
                    plot_min_max_avg_multi(
                        ax,
                        series_cache[key_obgp],
                        MODE_COLORS["oBGP"],
                        "oBGP avg",
                        ylim=ylimits[field],
                    )
                    if row == 0:
                        ax.set_title(label, fontsize=10.5, weight="bold")

            plt.tight_layout(rect=[0, 0.24, 1, 1])

            fig.legend(
                handles=[
                    Line2D([0], [0], color=MODE_COLORS["BGP"], lw=1.4, label="BGP Average"),
                    Line2D([0], [0], color=MODE_COLORS["oBGP"], lw=1.4, label="oBGP Average"),
                    Patch(facecolor="0.5", alpha=0.50, label="Mean Minimum and Maximum"),
                    Patch(facecolor="0.5", alpha=0.30, label="Global Minimum and Maximum"),
                ],
                loc="lower center",
                ncol=4,
                fontsize=8,
                frameon=False,
                bbox_to_anchor=(0.5, 0.20),
            )

            outfile = os.path.join(out_dir, f"{group_names[g_idx-1].replace(' ', '')}.pdf")
            plt.savefig(outfile)
            plt.close()
