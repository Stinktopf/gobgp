#!/usr/bin/env python3
import json
import matplotlib.pyplot as plt
import numpy as np

FILES = {
    "oBGP": "summary_obgp.json",
    "BGP": "summary_bgp.json"
}

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

def plot_min_max_avg(ax, series, color, title, ylabel, ylim=None):
    x = np.arange(len(series["avg"]))
    ax.plot(x, series["avg"], color=color, label="avg", linewidth=2)

    ax.fill_between(x, series["global_min"], series["global_max"],
                    color=color, alpha=0.1, label="global min–max")

    ax.fill_between(x, series["mean_min"], series["mean_max"],
                    color=color, alpha=0.3, label="mean min–max")

    ax.set_title(title, fontsize=13, weight="bold")
    ax.set_xlabel("Time in seconds", fontsize=11)
    ax.set_ylabel(ylabel, fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.legend()
    if ylim:
        ax.set_ylim(*ylim)

if __name__ == "__main__":
    fig, axes = plt.subplots(5, 2, figsize=(16, 20), sharex=True)

    data_obgp = load_summary(FILES["oBGP"])
    data_bgp = load_summary(FILES["BGP"])

    plots = [
        ("oBGP", data_obgp, "num_paths", "oBGP – Routes", "Number of routes"),
        ("BGP", data_bgp, "num_paths", "BGP – Routes", "Number of routes"),
        ("oBGP", data_obgp, "num_destinations", "oBGP – Prefixes", "Number of prefixes"),
        ("BGP", data_bgp, "num_destinations", "BGP – Prefixes", "Number of prefixes"),
        ("oBGP", data_obgp, "path_len_min", "oBGP – Min Path Length", "Path length"),
        ("BGP", data_bgp, "path_len_min", "BGP – Min Path Length", "Path length"),
        ("oBGP", data_obgp, "path_len_avg", "oBGP – Avg Path Length", "Average path length"),#
        ("BGP", data_bgp, "path_len_avg", "BGP – Avg Path Length", "Average path length"),
        ("oBGP", data_obgp, "path_len_max", "oBGP – Max Path Length", "Path length"),
        ("BGP", data_bgp, "path_len_max", "BGP – Max Path Length", "Path length"),
    ]


    series_data = {}
    for mode, data, field, title, ylabel in plots:
        series = extract_series(data, field=field)
        series_data[(mode, field)] = (series, title, ylabel)

    fields = set(field for _, _, field, _, _ in plots)
    ylimits = {}
    for field in fields:
        s1, _, _ = series_data[("oBGP", field)]
        s2, _, _ = series_data[("BGP", field)]
        min1, max1 = get_series_range(s1)
        min2, max2 = get_series_range(s2)
        ymin = min(min1, min2)
        ymax = max(max1, max2)
        margin = (ymax - ymin) * 0.05 if ymax > ymin else 1
        ylimits[field] = (ymin - margin, ymax + margin)

    for ax, (mode, data, field, title, ylabel) in zip(axes.flatten(), plots):
        series, _, _ = series_data[(mode, field)]
        plot_min_max_avg(ax, series, MODE_COLORS[mode], title, ylabel, ylim=ylimits[field])

    plt.tight_layout(rect=[0, 0, 1, 0.97])
    plt.show()
