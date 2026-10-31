// Small multiples of one scenario: per variant a line (the median over the
// runs of each run's mean over its routers), a band for the interval of that
// median, and on demand one from the smallest to the largest router, with
// a crosshair shared by all charts. The overview chooses which variants
// show, here and in its table, and which charts; the browser keeps both.
(() => {
  // [metric, title, unit, log]: update rates span from a few withdrawals to
  // thousands per second under oscillation, so they need a log-like scale.
  const METRICS = [
    ["destinations", "Routes", "prefixes with a route, per router", false],
    ["known", "Known", "prefixes with a path admitted or set aside, per router", false],
    ["blocked", "Blocked", "prefixes with a valid path set aside and no route, per router", false],
    ["adj_in", "Adj-RIB-In", "paths received, per router", false],
    ["paths", "Admitted", "paths per router · a count, not memory", false],
    ["suppressed", "Set aside", "paths per router", false],
    ["rss_mb", "Memory", "MiB per router · freed late", false],
    ["heap_mb", "Heap", "MiB per router · garbage until GC", false],
    ["heap_objects", "Heap objects", "per router · garbage until GC", false],
    ["cpu", "CPU", "% per router · whole daemon", false],
    ["path_len_avg", "Path length", "AS hops", false],
    ["churn", "BGP updates received", "per router and second · log scale", true],
  ];
  // The charts of the quality tab: how often the routers sampled and how
  // busy the host was, over the same time as the others.
  const QUALITY = [
    ["sample_rate", "Sampling rate", "Hz per router · band: slowest to fastest", false],
    ["host_cpu", "Host CPU", "% of all CPUs of the host", false],
  ];
  const { css, el } = UI;
  const stored = (key, fallback) => { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } };
  const store = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* private window */ } };
  const overview = document.getElementById("overview");
  const hiddenKey = `overview-hidden:${overview?.dataset.result}`;
  let hidden = new Set(stored(hiddenKey, []));
  // Every chart shows unless it was chosen away.
  const unchartedKey = "overview-uncharted";
  const uncharted = new Set(stored(unchartedKey, []));
  const charted = (metric) => !uncharted.has(metric);
  const loaded = new Map();  // src -> data, fetched once; filters only draw again
  // What goes with each median, one choice for the table and every chart:
  // the interval of the median over the runs (ci) or how the routers differ.
  let bandChoice = ["none", "ci", "routers"].includes(stored("overview-band", "none")) ? stored("overview-band", "none") : "none";
  const number = (v) => (v == null ? "–" : Math.abs(v) >= 100 ? Math.round(v).toLocaleString("en") : (+v.toFixed(2)).toString());
  // On axes, large numbers short: full tables hold millions of paths.
  const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
  const tick = (v) => (v == null ? "" : Math.abs(v) >= 10000 ? compact.format(v) : number(v));
  // Times on the axis, in minutes once runs take long.
  const clock = (x) => (x < 60 ? `${x} s` : x % 60 ? `${Math.floor(x / 60)} min ${x % 60} s` : `${x / 60} min`);
  const shown = new Map();  // root -> {charts, observer}, to clean up before drawing again

  async function render(root) {
    let data = loaded.get(root.dataset.src);
    if (!data) {
      try {
        const response = await fetch(root.dataset.src);
        if (!response.ok || !response.headers.get("content-type")?.includes("json")) throw new Error(response.status);
        data = await response.json();
        loaded.set(root.dataset.src, data);
      } catch {
        root.replaceChildren(UI.el("p", "muted py-6 text-center text-sm", "Could not load the charts. Sign in again or reload."));
        return;
      }
    }
    const quality = root.dataset.metrics === "quality";
    const band = root.dataset.spread || bandChoice;  // the quality tab always shows how the routers differ
    const list = quality ? QUALITY : METRICS.filter(([m]) => charted(m));
    const old = shown.get(root);
    old?.charts.forEach(([c]) => c.destroy());
    old?.observer.disconnect();
    // Eight colours of variants, then again. A colour stays with its variant
    // when others are hidden.
    const colors = data.variants.map((_, i) => css(`--series-${(i % 8) + 1}`));
    const shownVariants = data.variants.map((v, i) => [v, i]).filter(([v]) => !hidden.has(v));
    const muted = css("--chart-muted"), grid = css("--chart-grid"), axis = css("--chart-axis");
    const sync = uPlot.sync(root.dataset.src);
    const charts = [];
    let hovered = null;  // Only the chart under the pointer shows a tooltip; all show the crosshair.
    root.replaceChildren();

    // Runs that are not done yet have no series.
    const ran = (v) => Object.values(data.metrics).some((m) => m[v]?.median.some((x) => x != null));
    const waiting = shownVariants.filter(([v]) => !ran(v)).map(([v]) => v);
    if (waiting.length) {
      const all = waiting.length === shownVariants.length;
      root.append(el("p", "notice notice-warn mb-3",
        all ? "No run of this scenario is done yet. The charts appear once one is, after a reload."
          : `No run done yet for ${waiting.join(", ")}. Their lines appear once one is, after a reload.`));
      if (all) return;
    }
    // One legend for all charts, keyed with the line of each variant.
    const legend = el("div", "mb-3 flex flex-wrap gap-4 text-sm text-slate-600 dark:text-slate-300");
    shownVariants.forEach(([v, i]) => {
      const item = el("span", "flex items-center gap-2");
      const key = el("span", "inline-block h-0.5 w-5 rounded");
      key.style.background = colors[i];
      item.append(key, el("span", "font-mono", v));
      legend.append(item);
    });
    const first = data.events[data.variants[0]] || [];
    root.append(legend);

    const gridEl = el("div", "grid gap-4 md:grid-cols-2");
    root.append(gridEl);
    if (!list.length) gridEl.append(el("p", "card py-10 text-center text-sm text-slate-400 md:col-span-2", "Choose charts above."));
    for (const [metric, title, unit, log] of list) {
      const card = el("div", "card relative p-4");
      const head = el("div", "mb-2 flex items-baseline gap-2");
      head.append(el("h3", "text-sm font-medium", title), el("span", "ml-auto text-xs text-slate-500 dark:text-slate-400", unit));
      card.append(head);
      gridEl.append(card);
      const series = data.metrics[metric];
      if (!data.variants.some((v) => series[v].median.some((x) => x != null))) {
        card.append(el("p", "py-16 text-center text-sm text-slate-400", "Not recorded by these runs"));
        continue;
      }
      const plot = el("div");
      card.append(plot);
      const columns = [data.t];
      const specs = [{}];
      const bands = [];
      shownVariants.forEach(([v, i]) => {
        const s = series[v];
        columns.push(s.median);
        specs.push({ label: v, stroke: colors[i], width: 2, spanGaps: true, points: { show: false } });
        if (band === "ci") {
          columns.push(s.ci_high, s.ci_low);
          specs.push(
            { label: `${v} interval high`, stroke: "transparent", points: { show: false } },
            { label: `${v} interval low`, stroke: "transparent", points: { show: false } },
          );
          bands.push({ series: [specs.length - 2, specs.length - 1], fill: colors[i] + "33" });
        }
        if (band === "routers") {
          columns.push(s.max, s.min);
          specs.push(
            { label: `${v} largest router`, stroke: "transparent", points: { show: false } },
            { label: `${v} smallest router`, stroke: "transparent", points: { show: false } },
          );
          bands.push({ series: [specs.length - 2, specs.length - 1], fill: colors[i] + "26" });
        }
      });
      // The values at one time, for the tooltip and the lightbox.
      const describe = (i) => {
        const out = [el("div", "mb-1 text-slate-500 dark:text-slate-400", `${data.t[i]} s`)];
        for (const e of first.filter((e) => Math.floor(e.t) === data.t[i])) {
          out.push(el("div", "mb-1 font-medium text-slate-700 dark:text-slate-200", `▾ ${e.name.replaceAll("_", " ")}`));
        }
        shownVariants.forEach(([v, n]) => {
          const row = el("div", "flex items-center gap-2");
          const key = el("span", "inline-block h-0.5 w-3 rounded");
          key.style.background = colors[n];
          const s = series[v];
          row.append(key, el("span", "font-semibold tabular-nums text-slate-900 dark:text-white", number(s.median[i])),
            el("span", "tabular-nums text-slate-400", band === "routers"
              ? (s.min[i] != null && s.min[i] !== s.max[i] ? `routers ${number(s.min[i])}–${number(s.max[i])}` : "")
              : (s.ci_low[i] != null && s.ci_low[i] !== s.ci_high[i] ? `${number(s.ci_low[i])}–${number(s.ci_high[i])}` : "")),
            el("span", "font-mono text-slate-500 dark:text-slate-400", v));
          out.push(row);
        });
        return out;
      };
      // One chart in the grid, or large in the lightbox, where it zooms.
      const options = (width, height, zoom) => ({
        width,
        height,
        // asinh is logarithmic for large values and linear around zero, so 0 stays visible.
        // Linear scales start at zero, so sizes compare honestly.
        scales: { x: { time: false }, y: log ? { distr: 4, asinh: 1 } : { range: (u, min, max) => [0, max > 0 ? max * 1.08 : 1] } },
        series: specs,
        bands,
        legend: { show: false },
        cursor: zoom ? { y: false, drag: { x: true, y: true, uni: 30 }, points: { show: false } }
          : { sync: { key: sync.key }, y: false, drag: { x: false, y: false }, points: { show: false } },
        axes: [
          { stroke: muted, grid: { stroke: grid, width: 1 }, ticks: { stroke: axis, width: 1, size: 4 }, size: 28, gap: 4,
            incrs: [1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 900, 1200, 1800, 3600], values: (u, v) => v.map(clock) },
          { stroke: muted, grid: { stroke: grid, width: 1 }, ticks: { stroke: axis, width: 1, size: 4 }, gap: 4,
            values: (u, v) => v.map(tick),
            ...(log && !zoom ? { splits: (u, i, min, max) => [0, 1, 10, 100, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8].filter((x) => x <= Math.max(max, 1)) } : {}),
            // Wide enough for the longest label.
            size: (u, values) => 16 + 7 * Math.max(1, ...(values || []).map((v) => v.length)) },
        ],
        hooks: {
          // Events: a faint hairline with a mark at the top, once for all
          // variants (they play the same steps); names are in the tooltip.
          draw: [(u) => {
            const ctx = u.ctx, r = devicePixelRatio;
            const right = u.bbox.left + u.bbox.width;
            ctx.save();
            ctx.lineWidth = r;
            ctx.setLineDash([3 * r, 3 * r]);
            ctx.strokeStyle = axis;
            ctx.fillStyle = muted;
            for (const e of first) {
              const x = Math.round(u.valToPos(e.t, "x", true)) + 0.5;
              if (x < u.bbox.left || x > right) continue;
              ctx.beginPath();
              ctx.moveTo(x, u.bbox.top + 6 * r);
              ctx.lineTo(x, u.bbox.top + u.bbox.height);
              ctx.stroke();
              ctx.beginPath();
              ctx.moveTo(x - 3.5 * r, u.bbox.top);
              ctx.lineTo(x + 3.5 * r, u.bbox.top);
              ctx.lineTo(x, u.bbox.top + 5 * r);
              ctx.fill();
            }
            ctx.restore();
          }],
        },
      });
      const tooltip = el("div", "pointer-events-none absolute z-10 hidden rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs shadow-lg dark:border-slate-700 dark:bg-slate-800");
      card.append(tooltip);
      const small = options(plot.clientWidth || 400, 180, false);
      small.hooks.setCursor = [(u) => {
        const i = u.cursor.idx;
        if (i == null || u.cursor.left < 0 || hovered !== u) { tooltip.classList.add("hidden"); return; }
        tooltip.replaceChildren(...describe(i));
        tooltip.classList.remove("hidden");
        const left = u.cursor.left + u.over.offsetLeft;
        tooltip.style.left = `${Math.min(left + 12, card.clientWidth - tooltip.offsetWidth - 8)}px`;
        tooltip.style.top = `${u.cursor.top + u.over.offsetTop + 12}px`;
      }];
      const chart = new uPlot(small, columns, plot);
      const save = el("button", "rounded p-0.5 pointer-coarse:p-[15px] text-slate-400 hover:text-slate-700 dark:hover:text-slate-200");
      save.innerHTML = UI.icon("download");
      save.type = "button";
      save.dataset.tip = "Save as PNG";
      save.setAttribute("aria-label", `${title} as PNG`);
      save.onclick = () => png(chart, title, unit, shownVariants.map(([v, i]) => [v, colors[i]]));
      const large = () => lightbox({ title, unit, options, columns, describe, events: first, t: data.t,
        rows: shownVariants.map(([v]) => [v, series[v]]) });
      const expand = el("button", "rounded p-0.5 pointer-coarse:p-[15px] text-slate-400 hover:text-slate-700 dark:hover:text-slate-200");
      expand.innerHTML = UI.icon("expand");
      expand.type = "button";
      expand.dataset.tip = "Open large to zoom";
      expand.setAttribute("aria-label", `${title} large`);
      expand.onclick = large;
      head.append(expand, save);
      chart.over.addEventListener("click", large);
      chart.over.addEventListener("pointerenter", () => { hovered = chart; });
      chart.over.addEventListener("pointerleave", () => { hovered = null; tooltip.classList.add("hidden"); });
      charts.push([chart, plot]);
    }
    const observer = new ResizeObserver(() => charts.forEach(([c, p]) => c.setSize({ width: p.clientWidth, height: 180 })));
    observer.observe(gridEl);
    shown.set(root, { charts, observer });
  }

  // One chart large: dragging a box zooms into it, the wheel zooms the
  // y axis, a double click or Reset shows the whole run again. An interval
  // picks the whole run or the time from shortly before a step to the next.
  // The values under the cursor show below, the visible part saves as CSV.
  function lightbox({ title, unit, options, columns, describe, events, t, rows }) {
    const dialog = el("dialog", "dialog max-w-6xl");
    const body = el("div", "flex flex-col gap-3 p-4");
    const head = el("div", "flex flex-wrap items-center gap-2");
    head.append(el("h2", "section-title", title), el("span", "text-xs text-slate-500 dark:text-slate-400", unit));
    const interval = el("select", "input ml-auto w-auto");
    interval.setAttribute("aria-label", "Interval");
    const start = t[0], end = t[t.length - 1];
    const ranges = [["Whole run", start, end]];
    events.forEach((e, k) => {
      const next = events.slice(k + 1).find((n) => n.t > e.t)?.t ?? end;
      ranges.push([`${e.name.replaceAll("_", " ")} at ${clock(Math.floor(e.t))}`, Math.max(start, e.t - 5), next]);
    });
    ranges.forEach(([label], k) => interval.append(new Option(label, k)));
    const button = (text, tip) => {
      const b = el("button", "btn", text);
      b.type = "button";
      b.dataset.tip = tip;
      return b;
    };
    const reset = button("Reset", "Whole run, y axis to fit");
    const csv = button("CSV", "The visible part as CSV");
    const close = el("button", "btn btn-icon border-transparent shadow-none");
    close.type = "button";
    close.innerHTML = UI.icon("close");
    close.setAttribute("aria-label", "Close");
    close.onclick = () => dialog.close();
    head.append(interval, reset, csv, close);
    const plot = el("div");
    const values = el("div", "flex flex-wrap items-start gap-x-6 gap-y-1 text-xs");
    const hint = el("p", "text-xs text-slate-500 dark:text-slate-400",
      "Drag a box to zoom. The wheel zooms the y axis. A double click shows the whole run.");
    body.append(head, plot, values, hint);
    dialog.append(body);
    document.body.append(dialog);
    dialog.showModal();

    const height = () => Math.max(260, Math.round(innerHeight * 0.55));
    const opts = options(plot.clientWidth || 800, height(), true);
    opts.hooks.setCursor = [(u) => {
      const i = u.cursor.idx;
      if (i != null && u.cursor.left >= 0) values.replaceChildren(...describe(i));
    }];
    const chart = new uPlot(opts, columns, plot);
    if (columns[0].length) values.replaceChildren(...describe(columns[0].length - 1));  // the end of the run, until the cursor moves
    const show = (min, max) => chart.setScale("x", { min, max });
    interval.onchange = () => { const [, min, max] = ranges[+interval.value]; show(min, max); };
    reset.onclick = () => { interval.value = "0"; interval.dispatchEvent(new Event("change")); };
    // The wheel zooms around the pointer, in pixels, so the log scale zooms alike.
    chart.over.addEventListener("wheel", (e) => {
      e.preventDefault();
      const f = e.deltaY < 0 ? 0.8 : 1.25, h = chart.over.clientHeight, y = e.offsetY;
      const min = chart.posToVal(y + (h - y) * f, "y"), max = chart.posToVal(y - y * f, "y");
      if (Number.isFinite(min) && Number.isFinite(max) && max > min) chart.setScale("y", { min, max });
    }, { passive: false });
    csv.onclick = () => {
      const { min, max } = chart.scales.x;
      const header = ["t_s", ...rows.flatMap(([v]) => ["median", "ci_low", "ci_high", "min_router", "max_router"].map((k) => `${v} ${k}`))];
      const lines = [header.join(",")];
      t.forEach((x, i) => {
        if (x < min || x > max) return;
        lines.push([x, ...rows.flatMap(([, s]) => [s.median[i], s.ci_low[i], s.ci_high[i], s.min[i], s.max[i]].map((v) => v ?? ""))].join(","));
      });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([lines.join("\n") + "\n"], { type: "text/csv" }));
      a.download = `${title.toLowerCase().replaceAll(" ", "-")}-${Math.floor(min)}-${Math.ceil(max)}s.csv`;
      a.click();
      URL.revokeObjectURL(a.href);
    };
    const resize = () => chart.setSize({ width: plot.clientWidth, height: height() });
    addEventListener("resize", resize);
    dialog.addEventListener("click", (e) => { if (e.target === dialog) dialog.close(); });
    dialog.addEventListener("close", () => { removeEventListener("resize", resize); chart.destroy(); dialog.remove(); });
  }

  // A chart as PNG for slides, at the resolution of the screen or twice that:
  // its title, its legend and the plot on the colour of the card.
  function png(chart, title, unit, keys) {
    const scale = Math.max(2, devicePixelRatio), plot = chart.ctx.canvas, pad = 12 * scale, line = 18 * scale;
    const out = document.createElement("canvas");
    out.width = plot.width * (scale / devicePixelRatio);
    out.height = out.width / plot.width * plot.height + 2 * line + pad;
    const ctx = out.getContext("2d");
    ctx.fillStyle = getComputedStyle(chart.root.closest(".card")).backgroundColor;
    ctx.fillRect(0, 0, out.width, out.height);
    ctx.font = `600 ${13 * scale}px ui-sans-serif, system-ui, sans-serif`;
    ctx.fillStyle = getComputedStyle(chart.root.closest(".card")).color;
    ctx.fillText(`${title} · ${unit}`, pad, pad + 12 * scale);
    ctx.font = `${11 * scale}px ui-monospace, monospace`;
    let x = pad;
    for (const [name, color] of keys) {
      ctx.fillStyle = color;
      ctx.fillRect(x, pad + line + 4 * scale, 14 * scale, 2 * scale);
      ctx.fillStyle = getComputedStyle(chart.root.closest(".card")).color;
      ctx.fillText(name, x + 18 * scale, pad + line + 8 * scale);
      x += ctx.measureText(name).width + 32 * scale;
    }
    ctx.drawImage(plot, 0, 2 * line + pad, out.width, out.width / plot.width * plot.height);
    const a = document.createElement("a");
    a.href = out.toDataURL("image/png");
    a.download = `${title.toLowerCase().replaceAll(" ", "-")}.png`;
    a.click();
  }

  // The choices of the overview: which variants and which charts show.
  function choices() {
    if (!overview) return;
    const toggles = [...overview.querySelectorAll("[data-variant-toggle]")];
    const known = new Set(toggles.map((b) => b.dataset.variantToggle));
    hidden = new Set([...hidden].filter((v) => known.has(v)));
    if (hidden.size === known.size) hidden.clear();  // never none
    const count = overview.querySelector("[data-variant-count]");
    const apply = () => {
      for (const b of toggles) b.checked = !hidden.has(b.dataset.variantToggle);
      overview.querySelectorAll("[data-variant]").forEach((c) => (c.hidden = hidden.has(c.dataset.variant)));
      if (count) count.textContent = `${known.size - hidden.size} of ${known.size}`;
    };
    const changed = () => { store(hiddenKey, [...hidden]); apply(); init(); };
    for (const b of toggles) {
      b.onchange = () => {
        const v = b.dataset.variantToggle;
        if (b.checked) hidden.delete(v); else if (hidden.size < known.size - 1) hidden.add(v);
        changed();
      };
    }
    const all = overview.querySelector("[data-variant-all]");
    if (all) all.onclick = () => { hidden.clear(); changed(); };
    const find = overview.querySelector("[data-variant-find]");
    if (find) {
      find.oninput = () => overview.querySelectorAll("[data-variant-row]").forEach((row) => {
        row.hidden = !row.dataset.variantRow.includes(find.value.trim().toLowerCase());
      });
    }
    // The menu closes on a click elsewhere or on Escape.
    const menu = overview.querySelector("[data-variant-menu]");
    if (menu) {
      document.addEventListener("click", (e) => { if (!menu.contains(e.target)) menu.open = false; });
      menu.addEventListener("keydown", (e) => { if (e.key === "Escape") { menu.open = false; menu.querySelector("summary").focus(); } });
    }
    apply();
    // One choice for every toggle of the page: the table's marks, the bands, the whiskers.
    // A place where the choice gives nothing, e.g. no router spread for times, shows None.
    const showBand = () => {
      document.querySelectorAll("[data-band]").forEach((input) => {
        const mine = input.closest("[role=radiogroup]").querySelector(`[data-band][value="${bandChoice}"]`);
        input.checked = mine?.disabled ? input.value === "none" : input.value === bandChoice;
      });
      // In the table a range stands instead of its value, one number per cell.
      overview.querySelectorAll("[data-range]").forEach((r) => (r.hidden = r.dataset.range !== bandChoice));
      overview.querySelectorAll("[data-value]").forEach((v) => {
        const range = v.parentElement.querySelector(`[data-range="${bandChoice}"]`);
        v.hidden = bandChoice !== "none" && !!range;
      });
    };
    document.querySelectorAll("[data-band]").forEach((input) => (input.onchange = () => {
      bandChoice = input.value;
      store("overview-band", bandChoice);
      showBand();
      init();
    }));
    showBand();
    // The pickers of the charts: chips in the bar, on a phone the same as rows of a menu.
    const pickers = overview.querySelectorAll("[data-chart-picker]");
    const counted = () => overview.querySelectorAll("[data-chart-count]").forEach((c) => {
      c.textContent = `${METRICS.filter(([m]) => charted(m)).length} of ${METRICS.length}`;
    });
    // Short names on the chips, so that they fit a line; the charts keep their titles.
    const SHORT = { churn: "Updates", heap_objects: "Objects" };
    pickers.forEach((picker) => picker.replaceChildren(...picker.querySelectorAll(".label"), ...METRICS.map(([metric, title]) => {
      const chip = el("button", "chip chip-sm", SHORT[metric] || title);
      chip.type = "button";
      chip.dataset.chart = metric;
      chip.setAttribute("aria-pressed", charted(metric));
      chip.onclick = () => {
        if (uncharted.has(metric)) uncharted.delete(metric); else uncharted.add(metric);
        store(unchartedKey, [...uncharted]);
        overview.querySelectorAll(`[data-chart="${metric}"]`).forEach((c) => c.setAttribute("aria-pressed", charted(metric)));
        counted();
        init();
      };
      return chip;
    })));
    counted();
  }

  // A metric over the values of a sweep or the sizes of the topologies, as
  // dots and whiskers: per value a dot for the median of each variant, side
  // by side, and a whisker for the interval of the median, so that it shows
  // at a glance whether the variants differ. No line: between the values
  // nothing was measured. Drawn as SVG, small enough without a library.
  async function renderCurve(root) {
    let data;
    try {
      data = loaded.get(root.dataset.src) || (await (await fetch(root.dataset.src)).json());
      loaded.set(root.dataset.src, data);
    } catch {
      root.replaceChildren(el("p", "muted py-6 text-center text-sm", "Could not load the chart. Sign in again or reload."));
      return;
    }
    const shownVariants = data.variants.map((v, i) => [v, i]).filter(([v]) => !hidden.has(v));
    if (!data.x.length || !shownVariants.some(([v]) => data.series[v].median.some((x) => x != null))) {
      root.replaceChildren(el("p", "py-10 text-center text-sm text-slate-400", "No run done yet."));
      return;
    }
    const color = (i) => css(`--series-${(i % 8) + 1}`);
    const grid = css("--chart-grid"), axis = css("--chart-axis"), muted = css("--chart-muted"), surface = css("--chart-surface");
    const legend = el("div", "mb-2 flex flex-wrap gap-4 text-sm text-slate-600 dark:text-slate-300");
    for (const [v, i] of shownVariants) {
      const key = el("span", "inline-block size-2.5 rounded-full");
      key.style.background = color(i);
      const item = el("span", "flex items-center gap-2");
      item.append(key, el("span", "font-mono", v));
      legend.append(item);
    }
    const W = Math.max(320, root.clientWidth || 600), H = 230, left = 48, right = 8, top = 12, bottom = 40;
    const plotW = W - left - right, plotH = H - top - bottom;
    // The axis spans the data, not from zero: a dot shows by its place, not a
    // length, and the whiskers must not shrink to nothing under their dots.
    const ends = shownVariants.flatMap(([v]) => data.series[v].median.flatMap((m, j) => (bandChoice === "routers"
      ? [m, data.series[v].router_min[j], data.series[v].router_max[j]] : [m, data.series[v].ci_low[j], data.series[v].ci_high[j]]).filter((x) => x != null)));
    const lo0 = Math.min(...ends), hi0 = Math.max(...ends), pad = (hi0 - lo0) * 0.1 || Math.abs(hi0) * 0.1 || 1;
    const raw = (hi0 - lo0 + 2 * pad) / 4, mag = 10 ** Math.floor(Math.log10(raw)), step = [1, 2, 2.5, 5, 10].map((f) => f * mag).find((x) => x >= raw);
    const yMin = Math.max(lo0 >= 0 ? 0 : -Infinity, Math.floor((lo0 - pad) / step) * step), yMax = Math.ceil((hi0 + pad) / step) * step;
    const y = (v) => top + plotH - ((v - yMin) / (yMax - yMin)) * plotH;
    const column = plotW / data.x.length, k = shownVariants.length;
    const slot = Math.max(10, Math.min(28, column * 0.6 / k)), groupW = slot * k;  // a dot and its whisker per slot
    const unit = root.dataset.unit, n = (v, j) => data.series[v].n[j];
    let out = "";
    for (let t = yMin; t <= yMax + step / 2; t += step) {
      out += `<line x1="${left}" x2="${W - right}" y1="${y(t)}" y2="${y(t)}" stroke="${t === yMin ? axis : grid}" stroke-width="1"/>`;
      out += `<text x="${left - 6}" y="${y(t) + 4}" text-anchor="end" font-size="11" fill="${muted}">${tick(t)}</text>`;
    }
    data.x.forEach((x, j) => {
      const x0 = left + column * j + (column - groupW) / 2;
      out += `<text x="${left + column * (j + 0.5)}" y="${top + plotH + 16}" text-anchor="middle" font-size="11" fill="${muted}">${tick(x)}</text>`;
      shownVariants.forEach(([v, i], b) => {
        const s = data.series[v], m = s.median[j], cx = x0 + slot * (b + 0.5);
        if (m == null) return;
        const [low, high] = bandChoice === "routers" ? [s.router_min[j], s.router_max[j]] : bandChoice === "ci" ? [s.ci_low[j], s.ci_high[j]] : [null, null];
        if (low != null && high != null && high > low) {
          const lo = y(low), hi = y(high), cap = Math.min(5, slot / 2 - 1);
          const weak = bandChoice === "ci" && s.ci_level[j] < 0.95 ? ' stroke-dasharray="3 3"' : "";  // too few runs for 95 %
          out += `<path d="M${cx},${lo} V${hi} M${cx - cap},${lo} H${cx + cap} M${cx - cap},${hi} H${cx + cap}" stroke="${color(i)}" stroke-width="2" stroke-linecap="round" fill="none"${weak}/>`;
        }
        out += `<circle cx="${cx}" cy="${y(m)}" r="5" fill="${color(i)}" stroke="${surface}" stroke-width="2"/>`;
        const interval = bandChoice === "none" ? "" : bandChoice === "routers"
          ? (s.router_min[j] != null ? `&#10;routers ${number(s.router_min[j])} to ${number(s.router_max[j])}` : "&#10;the same for every router")
          : s.ci_low[j] != null ? `&#10;${(100 * s.ci_level[j]).toFixed(1)} % CI ${number(s.ci_low[j])} to ${number(s.ci_high[j])}${s.ci_level[j] < 0.95 ? `, ${n(v, j)} runs reach no 95 %` : ""}` : "&#10;no interval below 3 runs";
        out += `<rect x="${cx - slot / 2}" y="${top}" width="${slot}" height="${plotH}" fill="transparent" data-tip="${v} · ${data.label} ${tick(x)}&#10;median ${number(m)} ${unit}${interval}&#10;n = ${n(v, j)} runs"/>`;
      });
    });
    out += `<text x="${left + plotW / 2}" y="${H - 6}" text-anchor="middle" font-size="12" fill="${muted}">${data.label}</text>`;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("class", "block h-auto w-full");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `${unit} over ${data.label}, by variant`);
    svg.innerHTML = out;
    root.replaceChildren(legend, svg);
  }

  function init() {
    document.querySelectorAll("[data-charts]").forEach(render);
    document.querySelectorAll("[data-curve]").forEach(renderCurve);
  }
  document.addEventListener("DOMContentLoaded", choices);

  // A note once more runs are done than the page shows; it asks every five
  // seconds while the tab is visible.
  document.addEventListener("DOMContentLoaded", () => {
    const note = document.querySelector("[data-live]");
    if (!note) return;
    const shown = +note.dataset.done;
    const ask = async () => {
      if (document.visibilityState === "visible") {
        try {
          const { done, state } = await (await fetch(note.dataset.live)).json();
          if (done > shown) {
            note.querySelector("[data-live-text]").textContent = `${done - shown} new ${done - shown === 1 ? "run" : "runs"} since this page loaded.`;
            note.hidden = false;
          }
          if (state !== "running" && state !== "queued" && done <= shown) return;
        } catch { /* signed out or offline: ask again later */ }
      }
      setTimeout(ask, 5000);
    };
    setTimeout(ask, 5000);
  });
  document.addEventListener("DOMContentLoaded", init);
  document.addEventListener("lab:theme", init);
})();
