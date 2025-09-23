#!/usr/bin/env python3
import json
import numpy as np
import matplotlib.pyplot as plt
from scipy.signal import savgol_filter

FILES = {"oBGP": "report_obgp.json", "BGP": "report_bgp.json"}

METRICS = {
    "num_paths": "Number of routes",
    "num_destinations": "Number of destinations",
    "path_len_min": "Minimum path length",
    "path_len_max": "Maximum path length",
}

MODE_COLORS = {
    "oBGP": "#f15bb5",
    "BGP": "#00f5d4",
}

PHASE_COLORS = {
    "rising": "#9b5de5",
    "flat":   "#f15bb5",
    "falling": "#ff6b35",
}

SAMPLE_DT_SECONDS = 0.25
TREND_WINDOW_SECONDS = 1.5
TREND_EPS_FRAC = 0.000

PLATEAU_FRAC = 0.03
PLATEAU_SLOPE = 0.001
PLATEAU_WINDOW = 8
PLATEAU_MINLEN = 12

DERIV_WINDOW = 5
DERIV_POLY = 2

MIN_SEGMENT_LEN = 4


def load_median_series(filename, field):
    with open(filename, "r") as f:
        data = json.load(f)
    observers = data.get("observers", {})
    max_len = max(len(o["series"]) for o in observers.values())
    rows = []
    for o in observers.values():
        s = [pt.get(field, 0) for pt in o["series"]]
        if len(s) < max_len:
            s += [0] * (max_len - len(s))
        rows.append(s)
    return np.median(np.array(rows, float), axis=0)


def linear_slope(y):
    if len(y) < 2 or np.allclose(y, y[0]):
        return 0.0
    x = np.arange(len(y))
    a, _ = np.polyfit(x, y, 1)
    return float(a)


def detect_plateaus_raw(y, frac=PLATEAU_FRAC, slope_frac=PLATEAU_SLOPE,
                        window=PLATEAU_WINDOW, min_len=PLATEAU_MINLEN):
    n = len(y)
    if n == 0:
        return []
    H = float(np.max(y) - np.min(y)) or 1.0
    band = frac * H
    slope_thr = slope_frac * H
    out = []
    i = 0
    while i <= n - window:
        j = i + window
        while j <= n:
            seg = y[i:j]
            if np.ptp(seg) <= band and abs(linear_slope(seg)) <= slope_thr:
                j += 1
            else:
                break
        if j - i >= min_len:
            end = min(j - 1, n - 1)
            out.append((i, end))
            i = end + 1
        else:
            i += 1
    merged = []
    for s, e in out:
        if not merged or s > merged[-1][1] + 1:
            merged.append([s, e])
        else:
            merged[-1][1] = max(merged[-1][1], e)
    return [(int(s), int(e)) for s, e in merged]


def build_10s_trend_masks(y, dt=SAMPLE_DT_SECONDS, win_s=TREND_WINDOW_SECONDS, eps_frac=TREND_EPS_FRAC):
    n = len(y)
    H = float(np.max(y) - np.min(y)) or 1.0
    eps = eps_frac * H
    W = max(1, int(round(win_s / dt)))
    rising = np.zeros(n, bool)
    falling = np.zeros(n, bool)
    last = n - 1 - W
    for i in range(max(0, last + 1)):
        d = y[i + W] - y[i]
        if d > eps:
            rising[i:i + W + 1] = True
        elif d < -eps:
            falling[i:i + W + 1] = True
    if last < 0 and n > 1:
        d = y[-1] - y[0]
        if d > eps:
            rising[:] = True
        elif d < -eps:
            falling[:] = True
    return rising, falling


def labels_to_segments(labels):
    n = len(labels)
    segs = []
    cur = labels[0]
    start = 0
    for i in range(1, n):
        if labels[i] != cur:
            segs.append({"type": cur, "start": start, "end": i - 1})
            cur = labels[i]
            start = i
    segs.append({"type": cur, "start": start, "end": n - 1})
    return segs


def absorb_tiny_segments(segs, min_len=MIN_SEGMENT_LEN):
    if not segs:
        return segs
    out = [segs[0].copy()]
    for s in segs[1:]:
        if s["end"] - s["start"] + 1 < min_len:
            out[-1]["end"] = max(out[-1]["end"], s["end"])
        else:
            if s["start"] > out[-1]["end"] + 1:
                s["start"] = out[-1]["end"] + 1
            out.append(s.copy())
    merged = [out[0].copy()]
    for s in out[1:]:
        if s["type"] == merged[-1]["type"]:
            merged[-1]["end"] = max(merged[-1]["end"], s["end"])
        else:
            merged.append(s.copy())
    return merged


def classify_three_modes(y):
    y = np.asarray(y, float)
    n = len(y)
    assert n >= 1
    m_rise, m_fall = build_10s_trend_masks(y)
    label = np.empty(n, dtype=object)
    label[:] = None
    dy = savgol_filter(y, DERIV_WINDOW, DERIV_POLY, deriv=1)
    both = m_rise & m_fall
    label[both] = np.where(dy[both] >= 0, "rising", "falling")
    label[(m_rise) & (~both)] = "rising"
    label[(m_fall) & (~both)] = "falling"
    unknown = (label == None)
    if np.any(unknown):
        plateau_mask = np.zeros(n, bool)
        for s, e in detect_plateaus_raw(y):
            s = max(0, s)
            e = min(e, n - 1)
            if s <= e:
                plateau_mask[s:e + 1] = True
        take = unknown & plateau_mask
        label[take] = "flat"
    H = float(np.max(y) - np.min(y)) or 1.0
    slope_eps = PLATEAU_SLOPE * H
    unknown = (label == None)
    if np.any(unknown):
        up = dy[unknown] >= slope_eps
        down = dy[unknown] <= -slope_eps
        tmp = np.empty(np.count_nonzero(unknown), dtype=object)
        tmp[up] = "rising"
        tmp[down] = "falling"
        mid = ~(up | down)
        tmp[mid] = "flat"
        label[unknown] = tmp
    segs = labels_to_segments(label)
    segs = absorb_tiny_segments(segs, MIN_SEGMENT_LEN)
    final_labels = np.array(sum([[s["type"]] * (s["end"] - s["start"] + 1) for s in segs], []), dtype=object)
    return labels_to_segments(final_labels)


def shade(ax, segs):
    for s in segs:
        hatch = "///" if s["type"] == "rising" else ("..." if s["type"] == "flat" else "\\\\")
        ax.axvspan(
            s["start"] - 0.5, s["end"] + 0.5,
            facecolor=PHASE_COLORS[s["type"]],
            alpha=0.08,
            hatch=hatch,
            edgecolor=PHASE_COLORS[s["type"]],
            linewidth=0.0
        )


def plot_panel(ax, y, title, mode, ylabel):
    x = np.arange(len(y))
    ax.plot(x, y, lw=2, color=MODE_COLORS[mode])
    ax.set_title(title, fontsize=13, weight="bold", pad=12)
    ax.set_xlabel("Sample index", fontsize=11, labelpad=8)
    ax.set_ylabel(ylabel, fontsize=11, labelpad=8)
    ax.grid(True, alpha=0.3)


def print_report(title, segs):
    print(f"=== {title} ===")
    for s in segs:
        ln = s["end"] - s["start"] + 1
        print(f"  {s['type']:7s} {s['start']:>4d}-{s['end']:<4d} (len={ln:>3d})")
    print()


if __name__ == "__main__":
    fig, axes = plt.subplots(len(METRICS), 2, figsize=(16, 20), sharex=True)
    for col, mode in enumerate(FILES):
        for row, (field, label) in enumerate(METRICS.items()):
            y = load_median_series(FILES[mode], field)
            segs = classify_three_modes(y)
            ax = axes[row, col]
            plot_panel(ax, y, f"{mode} – {label}", mode, label)
            shade(ax, segs)
            print_report(f"{mode} – {label}", segs)

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    fig.subplots_adjust(hspace=0.4)
    plt.show()
