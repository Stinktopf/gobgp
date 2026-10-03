// The largest value, at least 1. Math.max(...values) fails on long runs:
// hundreds of thousands of arguments exceed the call stack.
const largest = (values) => values.reduce((m, v) => (v > m ? v : m), 1);

// Replay of a run on its topology, every variant on one clock from t = 0,
// by time or by steps (clock.js).
// Routers glow blue with the updates they receive per second, sized by
// their admitted, suppressed or received paths, and ringed while they hold
// every expected prefix. Routers that run OBGP in a hybrid are squares. Links carry
// moving dashes as fast as their updates; down links are dashed and faded,
// degraded ones dotted.
(() => {
  const root = document.getElementById("replay");
  if (!root) return;
  const q = (sel, scope = root) => scope.querySelector(sel);
  const css = UI.css;
  const variants = JSON.parse(root.dataset.variants);
  // The variants shown side by side, at most four at first; the browser keeps them.
  const shownKey = `replay-shown:${root.dataset.result}`;
  let shown = (() => { try { return JSON.parse(localStorage.getItem(shownKey)); } catch { return null; } })();
  shown = new Set((shown || variants.slice(0, 4)).filter((v) => variants.includes(v)));
  if (!shown.size) shown = new Set(variants.slice(0, 4));
  // A link to one run of a variant shows that variant.
  const wanted = new URLSearchParams(location.search).get("variant");
  if (variants.includes(wanted)) shown.add(wanted);
  const visible = () => variants.filter((v) => shown.has(v));
  const color = (name) => css(`--series-${(variants.indexOf(name) % 8) + 1}`);
  const params = () => Object.fromEntries([...root.querySelectorAll("[data-param]")].map((s) => [s.dataset.param, s.value]));

  let runs = {}, graphs = {};
  let now = 0, end = 1, playing = false, last = null, frame = 0;
  let scale = { churn: 1, link: 1, size: 1 };
  // Runs before 2026-10 only know the admitted paths.
  const sizeBy = () => {
    const chosen = root.querySelector("input[name=size]:checked")?.value || "paths";
    return chosen === "paths" || Object.values(runs).every((r) => r.sizes) ? chosen : "paths";
  };
  let heat = null, colors = {};
  let loads = 0;
  const loaded = {};  // the data of the shown run, per variant
  let clock = null;

  const makeClock = () => ReplayClock.make(runs, root.querySelector("input[name=clock]:checked")?.value === "steps");

  // Colours of the tokens, read once per colour scheme.
  function palette() {
    heat = Graph.ramp("--activity-low", "--activity-high");
    colors = Object.fromEntries(["--graph-node", "--graph-label", "--graph-edge", "--activity-halo"].map((t) => [t, css(t)]));
  }

  // Seconds as text; a moment just before 0, e.g. -0.001 s, is 0.0 s.
  const seconds = (t) => {
    t = Math.max(0, t);
    return t < 60 ? `${t.toFixed(1)} s` : `${Math.floor(t / 60)} min ${(t % 60).toFixed(1).padStart(4, "0")} s`;
  };
  const level = (value, max) => (value > 0 ? Math.log1p(value) / Math.log1p(max) : 0);
  const frameAt = (run, t) => {
    let lo = 0, hi = run.t.length - 1;
    if (!run.t.length || t < run.t[0]) return -1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (run.t[mid] <= t) lo = mid; else hi = mid - 1; }
    return lo;
  };

  // What is down or degraded at t, from the events
  function failures(run, t) {
    const links = new Map(), routers = new Set();
    const key = (l) => [...l].sort().join("|");
    for (const e of run.events) {
      if (e.t > t) break;
      if (e.name === "down") {
        if (e.mode === "session") (e.routers || []).forEach((r) => routers.add(r));
        e.links.forEach((l) => links.set(key(l), "down"));
      } else if (e.name === "degrade") {
        e.links.forEach((l) => { if (!links.has(key(l))) links.set(key(l), "degraded"); });
      } else if (e.name === "up") {
        (e.routers || []).forEach((r) => routers.delete(r));
        e.links.forEach((l) => links.delete(key(l)));
      }
    }
    return { links, routers };
  }

  function build(name, data) {
    const pane = q(`[data-pane="${name}"]`);
    graphs[name]?.destroy();
    graphs[name] = Graph.view(q("[data-graph]", pane), data.topology, { node: 11, label: 10, padding: 36, styles: [
      { selector: "node", style: { "border-color": colors["--graph-label"], "underlay-shape": "ellipse",
        "underlay-color": colors["--activity-halo"], "text-background-opacity": 0 } },
      { selector: "node.origin", style: { "background-color": colors["--graph-label"] } },
      { selector: "edge", style: { "line-dash-pattern": [6, 5] } },
    ] });
    graphs[name].on("zoom", () => draw());
    // A router clicked shows its table over the run, from the frames loaded already.
    graphs[name].on("tap", (e) => {
      if (e.target === graphs[name]) delete picked[name];
      else if (e.target.isNode?.()) picked[name] = e.target.id();
      chart(name);
      draw();
    });
  }

  // The sizes of the table of the router picked in a pane, over the run, with
  // a line at the time shown. Older runs have the paths only.
  const picked = {};
  const SERIES = [["paths", "Admitted", 1], ["adj_in", "Adj-RIB-In", 2], ["suppressed", "Suppressed", 3]];
  function chart(name) {
    const pane = q(`[data-pane="${name}"]`), box = q("[data-router]", pane), run = runs[name];
    const f = run?.routers[picked[name]];
    box.hidden = !f;
    if (!f) return;
    const shown = SERIES.filter(([key]) => (key === "paths" || run.sizes) && f[key]?.some((v) => v));
    const W = 270, H = 64, t0 = run.t[0] ?? 0, span = (run.t.at(-1) ?? 1) - t0 || 1;
    const top = largest(shown.flatMap(([key]) => f[key]));
    const x = (t) => ((t - t0) / span) * W, y = (v) => H - 2 - (v / top) * (H - 4);
    const svg = `<svg viewBox="0 0 ${W} ${H}" class="mt-1.5 block h-16 w-full overflow-visible">${shown.map(([key, , c]) =>
      `<polyline fill="none" stroke="var(--series-${c})" stroke-width="1.5" vector-effect="non-scaling-stroke" points="${run.t.map((t, i) => `${x(t).toFixed(1)},${y(f[key][i]).toFixed(1)}`).join(" ")}"/>`).join("")}
      <line data-cursor y1="0" y2="${H}" stroke="currentColor" stroke-opacity="0.4" vector-effect="non-scaling-stroke"/></svg>`;
    box.innerHTML = `<div class="flex items-baseline justify-between gap-2"><span class="font-mono font-medium">${picked[name]}</span>
      <span class="muted">table over the run, up to ${top.toLocaleString("en")}</span></div>${svg}
      <div class="mt-1 flex flex-wrap gap-x-3">${shown.map(([key, label, c]) =>
        `<span><span class="mr-1 inline-block h-2 w-2 rounded-full" style="background: var(--series-${c})"></span>${label} <span class="tabular-nums" data-value="${key}"></span></span>`).join("")}</div>`;
    box.dataset.x0 = t0;
    box.dataset.span = span;
  }
  function cursor(name, at, i) {
    const box = q(`[data-pane="${name}"] [data-router]`), f = runs[name]?.routers[picked[name]];
    if (!f || box.hidden) return;
    q("[data-cursor]", box)?.setAttribute("transform", `translate(${(((at - box.dataset.x0) / box.dataset.span) * 270).toFixed(1)} 0)`);
    box.querySelectorAll("[data-value]").forEach((v) => (v.textContent = i >= 0 ? f[v.dataset.value][i].toLocaleString("en") : ""));
  }

  function draw(dt = 0) {
    for (const [name, run] of Object.entries(runs)) {
      const cy = graphs[name];
      if (!cy) continue;
      const pane = q(`[data-pane="${name}"]`);
      const at = clock.toRun(run, now);
      const i = frameAt(run, at);
      const { "--graph-node": node, "--graph-label": text, "--graph-edge": edge } = colors;
      const zoom = cy.zoom();
      const { links, routers } = failures(run, at);
      const expected = i >= 0 ? run.expected[i] : null;
      let total = 0, complete = 0, watched = 0;
      cy.batch(() => {
        cy.nodes().forEach((n) => {
          const f = run.routers[n.id()];
          // Label sizes are set here too: Cytoscape keeps the sizes of the
          // style from before the first zoom of a graph built off screen.
          if (!f || n.hasClass("origin")) { n.style({ "font-size": 10 / zoom, "text-margin-y": 4 / zoom }); return; }  // not sampled
          const churn = i >= 0 ? f.churn[i] : 0, paths = i >= 0 ? f[sizeBy()][i] : 0;
          const v = level(churn, scale.churn);
          const off = routers.has(n.id());
          const full = i >= 0 && expected != null && f.destinations[i] === expected;
          total += churn; watched++; complete += full;
          const size = (6 + 20 * Math.sqrt(paths / scale.size)) / zoom;
          n.style({
            "background-color": off ? "transparent" : heat(v), width: size, height: size,
            "border-width": (off ? 1.5 : full ? 2 : 0) / zoom, "border-style": off ? "dashed" : "solid",
            "border-color": off ? node : text,
            "underlay-opacity": off ? 0 : 0.35 * v, "underlay-padding": (4 + 14 * v) / zoom,
            "font-size": 10 / zoom, "text-margin-y": 4 / zoom,
          });
        });
        cy.edges().forEach((e) => {
          const state = links.get(e.id()) || (routers.has(e.source().id()) || routers.has(e.target().id()) ? "down" : null);
          const rate = i >= 0 && run.links[e.id()] ? run.links[e.id()][i] : 0;
          const v = state ? 0 : level(rate, scale.link);
          // Dashes move with the updates on the link.
          const offset = ((e.scratch("offset") || 0) - dt * 60 * v) % 1100;
          e.scratch("offset", offset);
          e.style({
            "line-color": state ? node : v ? heat(0.25 + 0.75 * v) : edge,
            "line-style": state === "down" ? "dashed" : state === "degraded" ? "dotted" : v ? "dashed" : "solid",
            "line-dash-offset": offset, opacity: state === "down" ? 0.5 : 1, width: (state ? 1.5 : 1.5 + 3.5 * v) / zoom,
          });
        });
      });
      cursor(name, at, i);
      q("[data-stats] span", pane).textContent = i < 0 ? "" : `${seconds(at)} · ${Math.round(total).toLocaleString("en")} upd/s · ${complete}/${watched}`;
    }
    q("[data-clock]").textContent = seconds(now);
    q("[data-scrub]").value = Math.round(now * 10);
    const recent = clock?.events.filter((e) => e.c <= now).at(-1);
    q("[data-event]").textContent = recent
      ? [describe(recent), ...settingsOf(recent).map(([label, value]) => `${label} ${value}`), seconds(recent.c)].join(" · ") : "";
  }

  // An event in words, e.g. "Link toronto–fulda cut, silently".
  const and = (names) => (names.length < 3 ? names.join(" and ") : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`);
  const links = (e) => (e.links || []).map((l) => l.join("–"));
  const outcome = (stable) => (stable ? "stable" : "not stable within the timeout");
  // The parameters of an action, as label and value, shown under it.
  function settingsOf(e) {
    const out = [];
    if (e.name === "set_preference" && e.value) out.push(["Local Preference", e.value]);
    if (e.name === "prepend") out.push(["Times", e.times]);
    if (e.name === "soft_reset") out.push(["Direction", { in: "routes asked for", out: "routes sent", both: "both" }[e.direction] ?? e.direction]);
    if (e.name === "expect" && !e.each) {
      out.push(["Result", e.passed ? "passed" : "failed"]);
      for (const problem of e.problems || []) out.push(["Problem", problem]);
    }
    if (e.name === "degrade") {
      if (e.delay_ms) out.push(["Delay", `${e.delay_ms} ms`]);
      if (e.jitter_ms) out.push(["Jitter", `${e.jitter_ms} ms`]);
      if (e.loss_pct) out.push(["Loss", `${e.loss_pct} %`]);
    }
    if (e.name === "withdraw" && e.percent != null && e.percent < 100) out.push(["Share", `${e.percent} %`]);
    if (e.name === "originate") {
      out.push(["Prefixes", e.prefixes?.length ?? 0]);
      if (e.more_specific) out.push(["More specific", "yes"]);
    }
    if (e.expected != null) out.push(["In the network", `${e.expected} prefixes`]);
    return out;
  }
  function describe(e) {
    // Runs of the former scripts do not name the routers: the origins acted.
    const named = e.routers || [], routers = named.length ? and(named) : "The origins", many = named.length !== 1;
    // A router takes its links along, so it is named alone.
    const targets = named.length ? `${many ? "Routers" : "Router"} ${routers}`
      : links(e).length ? `${links(e).length > 1 ? "Links" : "Link"} ${and(links(e))}` : "";
    const mode = { session: "", cut: ", silently", oneway: ", in one direction" }[e.mode] ?? "";
    switch (e.name) {
      case "announce": return `${routers} ${many ? "announce" : "announces"} prefixes`;
      case "announce_rib": return `${routers} ${many ? "inject" : "injects"} the full table of ${e.table} UTC, ${(e.prefixes ?? 0).toLocaleString("en")} prefixes`;
      case "announced": return `${routers} ${many ? "stop" : "stops"} announcing`;
      case "withdraw": return `${routers} ${many ? "withdraw" : "withdraws"} ${(e.percent ?? 100) < 100 ? "some" : "all"} of ${many ? "their" : "its"} prefixes`;
      case "originate": return `${routers} also ${many ? "announce" : "announces"} prefixes of other routers`;
      case "down": return named.length && e.mode !== "session" ? `${targets} cut off${mode}` : `${targets} down${mode}`;
      case "up": return targets ? `${targets} back up` : "Everything back up";
      case "degrade": return `${targets} degraded`;
      case "restart": return `${routers} ${many ? "restart" : "restarts"}${e.graceful ? " gracefully" : ""}`;
      case "set_preference": return e.value ? `${routers} prefers routes from ${e.neighbor}` : `${routers} drops its preference for ${e.neighbor}`;
      case "prepend": return `${routers} ${many ? "prepend their" : "prepends its"} AS`;
      case "set_export": return `${e.allow ? `${routers} announces routes to ${e.neighbor} again` : `${routers} stops announcing routes to ${e.neighbor}`}, outside the model`;
      case "soft_reset": return `${routers} ${many ? "refresh their" : "refreshes its"} routes`;
      case "expect": {
        const what = [{ none: "hold no prefixes", any: null }[e.prefixes] ?? "hold all prefixes", e.via && `route via ${e.via}`, e.avoid && `avoid ${e.avoid}`];
        return `Check: ${routers} ${and(what.filter(Boolean))}`;
      }
      case "settled": return e.each ? e.each.map(([n, stable]) => `${n} ${outcome(stable)}`).join(", ") : outcome(e.stable);
      default: return `${e.name.replaceAll("_", " ")} ${targets}`.trim();
    }
  }

  // The lanes of the timeline: updates per second, phases and actions.
  // By steps all variants share one lane, on the common clock; by time
  // each variant has its own, as its events are at times of its own.

  function activity() {
    const box = q("[data-lanes]");
    const names = Object.keys(runs);
    const lanes = clock.holds || names.length < 2
      ? [{ names, events: clock.events }]
      : names.map((name) => ({ names: [name], events: runs[name].events.map((e) => ({ ...e, c: e.t })), own: name }));
    box.replaceChildren(...lanes.map(() => {
      const lane = UI.el("div");
      lane.innerHTML = `<div data-row="actions" class="relative mx-2"></div><canvas class="mx-2 block h-11 w-[calc(100%-1rem)]"></canvas><div data-row="phases" class="relative mx-2"></div>`;
      return lane;
    }));
    // One scale for every lane, so that they compare.
    const totals = Object.fromEntries(Object.entries(runs).map(([name, r]) =>
      [name, r.t.map((_, i) => Object.values(r.routers).reduce((s, f) => s + f.churn[i], 0))]));
    const max = largest(Object.values(totals).flat());
    lanes.forEach((lane, i) => drawLane(box.children[i], lane, totals, max));
  }

  function drawLane(element, lane, totals, max) {
    const canvas = element.querySelector("canvas");
    const ratio = window.devicePixelRatio || 1;
    canvas.width = canvas.clientWidth * ratio;
    canvas.height = canvas.clientHeight * ratio;
    const c = canvas.getContext("2d");
    c.scale(ratio, ratio);
    const w = canvas.clientWidth, h = canvas.clientHeight - 1;
    const x = (t) => (t / end) * w;
    // Phases, from each event to the next, in turn tinted in two colours;
    // events closer than a few pixels are one edge, e.g. the end of a step
    // and the action right after it. Times before 0 or after the end are
    // clamped to it, e.g. an action at -0.0 s by its own clock.
    const edges = [{ c: 0, events: [] }];
    for (const e of [...lane.events].sort((a, b) => a.c - b.c)) {
      const at = Math.min(end, Math.max(0, e.c));
      if (x(at) - x(edges.at(-1).c) >= 3) edges.push({ c: at, events: [] });
      edges.at(-1).events.push(e);
    }
    edges.push({ c: end, events: [] });
    const tints = [css("--phase-a"), css("--phase-b")];
    for (let k = 0; k < edges.length - 1; k++) {
      c.fillStyle = tints[k % 2];
      c.fillRect(x(edges[k].c), 0, x(edges[k + 1].c) - x(edges[k].c), h + 1);
    }
    markers(element, x, edges, lane.own);
    // Sampled on the common clock, so that it shows what the panes show,
    // including a run that holds while another finishes its step.
    for (const name of lane.names) {
      const r = runs[name], values = totals[name];
      if (!r.t.length || r.counters === false) continue;
      const points = [];
      for (let px = 0; px <= w; px++) {
        const t = clock.toRun(r, (px / w) * end);
        if (t < r.t[0]) continue;
        if (!clock.holds && t > r.t.at(-1)) break;
        points.push([px, h - level(values[frameAt(r, t)], max) * (h - 4)]);
      }
      if (!points.length) continue;
      c.beginPath();
      points.forEach(([px, y], i) => (i ? c.lineTo(px, y) : c.moveTo(px, y)));
      c.strokeStyle = color(name);
      c.lineWidth = 1.5;
      c.stroke();
      c.lineTo(points.at(-1)[0], h);
      c.lineTo(points[0][0], h);
      c.fillStyle = color(name) + "22";
      c.fill();
    }
    // A line at every action, under its icon, over the curves.
    c.strokeStyle = css("--action-line");
    c.lineWidth = 1.5;
    for (const edge of edges.filter((edge) => edge.events.some((e) => !ENDS.has(e.name)))) {
      const px = Math.min(w - 1, Math.max(1, x(edge.c)));
      c.beginPath();
      c.moveTo(px, 0);
      c.lineTo(px, h + 1);
      c.stroke();
    }
    // Without counters there is no activity to show, which is not none.
    if (lane.names.every((name) => runs[name].counters === false)) {
      c.fillStyle = css("--chart-muted");
      c.font = `11px ${getComputedStyle(document.body).fontFamily}`;
      c.textBaseline = "middle";
      c.fillText("Updates not recorded", 8, h / 2);
    }
    // The lane of one variant, in its colour at the left.
    if (lane.own) {
      c.fillStyle = color(lane.own);
      c.fillRect(0, 0, 3, h + 1);
    }
  }

  // Above the strip the actions, each over the line at its moment, those
  // at the same moment, e.g. of a parallel step, stacked upwards; below
  // the scrubber the phases, each under its middle, named by how it ends:
  // the end of an until_stable, the end of announcing, or else the next
  // action after a wait. A marker that would cover the one before moves
  // aside, and none leaves the strip. A click jumps to the action, or to
  // the start of the phase.
  const ENDS = new Set(["announced", "settled"]);
  function markers(element, x, edges, own) {
    const actions = [];
    for (const edge of edges) {
      const here = edge.events.filter((e) => !ENDS.has(e.name));
      if (here.length) {
        const text = here.map(describe).join(", ");
        actions.push({ center: x(edge.c), at: edge.c, icons: here.map((e) => e.name), tip: `${text} · ${seconds(edge.c)}`,
                       build: () => (here.length > 1
                         ? tipOf(tipLine("tip-head", null, "At once", seconds(edge.c)), ...here.flatMap((e) => [tipLine("tip-row", e.name, describe(e)), ...detailOf(e), ...checked(e)]))
                         : tipOf(tipLine("tip-head", here[0].name, describe(here[0]), seconds(edge.c)), ...detailOf(here[0]), ...checked(here[0]))) });
      }
    }
    const phases = [];
    for (let k = 0; k < edges.length - 1; k++) {
      const [from, to] = [edges[k].c, edges[k + 1].c];
      const ending = edges[k + 1].events;
      const settled = ending.find((e) => e.name === "settled");
      const [icon, what] = settled ? ["until_stable", "Until stable"]
        : ending.some((e) => e.name === "announced") ? ["announce", "Announcing"]
        : k + 1 < edges.length - 1 ? ["wait", "Waiting"] : [null, null];
      // How each variant ended it, or the one of this lane.
      const each = settled ? settled.each || [[own, settled.stable]] : [];
      if (icon && x(to) - x(from) >= 3) {
        const span = `${seconds(from)} – ${seconds(to)}`;
        phases.push({ center: (x(from) + x(to)) / 2, at: from, icons: [icon], tip: `${what} · ${span}`,
                      build: () => tipOf(tipLine("tip-head", icon, what, span), ...each.map(([name, stable]) => verdict(name, stable))) });
      }
    }
    place(element.querySelector('[data-row="actions"]'), actions, true);
    place(element.querySelector('[data-row="phases"]'), phases, false);
  }

  // Parts of the tooltips of the markers.
  function detailOf(e) {
    const list = settingsOf(e);
    if (!list.length) return [];
    const grid = UI.el("dl", "tip-params");
    for (const [label, value] of list) grid.append(UI.el("dt", "", label), UI.el("dd", "", String(value)));
    return [grid];
  }
  const tipOf = (...parts) => { const f = document.createDocumentFragment(); f.append(...parts); return f; };
  function tipLine(cls, icon, text, time) {
    const line = UI.el("div", cls);
    if (icon) line.insertAdjacentHTML("beforeend", UI.icon(icon));
    line.append(UI.el("span", "min-w-0", text));
    if (time) line.append(UI.el("span", "tip-time", time));
    return line;
  }
  // How a check went in each variant.
  function checked(e) {
    if (e.name !== "expect" || !e.each) return [];
    return e.each.flatMap(([name, passed, problems]) => {
      const line = UI.el("div", "tip-row items-center");
      const dot = UI.el("span", "size-2 shrink-0 rounded-full");
      dot.style.background = color(name);
      line.append(dot, UI.el("span", "font-mono", name), UI.el("span", passed ? "text-emerald-300" : "text-red-300", passed ? "passed" : "failed"));
      return [line, ...problems.map((p) => UI.el("div", "tip-row pl-4 text-slate-300", p))];
    });
  }
  function verdict(name, stable) {
    const line = UI.el("div", "tip-row items-center");
    if (name) {
      const dot = UI.el("span", "size-2 shrink-0 rounded-full");
      dot.style.background = color(name);
      line.append(dot, UI.el("span", "font-mono", name));
    }
    line.append(UI.el("span", stable ? "text-emerald-300" : "text-amber-300", stable ? "stable" : "not stable within the timeout"));
    return line;
  }

  function place(box, items, stacked) {
    const width = (item) => (!stacked ? 18 * item.icons.length : item.icons.length > 1 ? 22 : 18);
    // A stack of parallel actions has room between its icons and a frame.
    const tall = (item) => (stacked && item.icons.length > 1 ? 6 + 18 * item.icons.length : 18);
    box.style.height = `${6 + Math.max(18, ...items.map(tall))}px`;  // 4 px from the strip, above as below
    let right = -Infinity;
    for (const item of items) {
      item.left = Math.max(item.center - width(item) / 2, right + 1);
      right = item.left + width(item);
    }
    let limit = box.clientWidth;
    for (let k = items.length - 1; k >= 0; k--) {
      items[k].left = Math.max(0, Math.min(items[k].left, limit - width(items[k])));
      limit = items[k].left - 1;
    }
    box.replaceChildren(...items.map((item) => {
      const group = stacked && item.icons.length > 1 ? "gap-1 p-1 ring-1 ring-slate-300 dark:ring-slate-600" : "p-0.5";
      const b = UI.el("button", `absolute ${stacked ? "bottom-1 flex-col-reverse" : "top-1"} ${group} flex rounded-md text-slate-400 hover:bg-slate-100 hover:text-slate-900 dark:hover:bg-slate-800 dark:hover:text-white`);
      b.type = "button";
      b.style.left = `${item.left}px`;
      b.innerHTML = item.icons.map((name) => UI.icon(name, "size-3.5")).join("");
      b.dataset.tip = item.tip;
      if (item.build) b.tip = item.build;
      if (item.left > box.clientWidth * 0.6) b.dataset.tipAlign = "end";
      b.setAttribute("aria-label", item.tip);
      b.onclick = () => { toggle(false); now = item.at; draw(); };
      return b;
    }));
  }

  // Loading

  async function load() {
    const p = params(), load = ++loads;
    const url = (variant) => `/results/${root.dataset.result}/replay?${new URLSearchParams({ topology: p.topology, scenario: p.scenario, run: p.run, variant })}`;
    let answers;
    try {
      answers = await Promise.all(visible().filter((v) => !loaded[v]).map(async (v) => {
        const response = await fetch(url(v));
        if (!response.ok || !response.headers.get("content-type")?.includes("json")) throw new Error(response.status);
        return [v, await response.json()];
      }));
    } catch {
      if (load === loads) q("[data-event]").textContent = "Could not load the run. Sign in again or reload.";
      return;
    }
    if (load !== loads) return;  // a newer choice is loading
    for (const [v, data] of answers) loaded[v] = data;
    show();
  }

  // Draws the loaded run, e.g. again for another colour scheme.
  function show() {
    palette();
    runs = {};
    for (const name of variants) {
      const pane = q(`[data-pane="${name}"]`);
      pane.hidden = !shown.has(name);
      const data = loaded[name];
      if (!data || pane.hidden) { graphs[name]?.destroy(); delete graphs[name]; continue; }
      q("[data-missing]", pane).hidden = !data.missing;
      q("[data-status]", pane).textContent = data.status || "";
      if (data.missing) { graphs[name]?.destroy(); delete graphs[name]; q("[data-stats] span", pane).textContent = ""; continue; }
      runs[name] = data;
      build(name, data);
      chart(name);
    }
    const all = Object.values(runs);
    const peak = (pick) => largest(all.flatMap(pick));
    scale = {
      churn: peak((r) => Object.values(r.routers).flatMap((f) => f.churn)),
      link: peak((r) => Object.values(r.links).flat()),
      // One scale for all sizes, the Adj-RIB-In, so that switching compares.
      size: peak((r) => Object.values(r.routers).flatMap((f) => (r.sizes ? f.adj_in : f.paths))),
    };
    root.querySelectorAll("[data-size-new]").forEach((label) => (label.hidden = !all.every((r) => r.sizes)));
    // Older runs have the admitted paths only: those are chosen then, not a hidden one.
    if (!all.every((r) => r.sizes)) root.querySelector("input[name=size][value=paths]").checked = true;
    clock = makeClock();
    end = clock.end;
    now = Math.max(0, Math.min(now, end));
    q("[data-scrub]").max = Math.round(end * 10);
    activity();
    draw();
  }

  // Playback

  function tick(time) {
    if (!playing) return;
    const dt = last == null ? 0 : (time - last) / 1000;
    last = time;
    now = Math.min(end, now + dt * +root.querySelector("input[name=speed]:checked").value);
    draw(dt);
    if (now >= end) {
      if (!looping) { toggle(false); return; }
      now = 0;  // from the start again
    }
    frame = requestAnimationFrame(tick);
  }
  // Playing loops unless switched off; the choice stays with the browser.
  let looping = true;
  try { looping = localStorage.getItem("replay-loop") !== "off"; } catch {}
  function showLoop() {
    const b = q("[data-loop]");
    b.setAttribute("aria-pressed", looping);
    b.dataset.tip = looping ? "Loop: on" : "Loop: off";
    b.setAttribute("aria-label", b.dataset.tip);
  }
  q("[data-loop]").onclick = () => {
    looping = !looping;
    try { localStorage.setItem("replay-loop", looping ? "on" : "off"); } catch {}
    showLoop();
  };
  showLoop();
  function toggle(on = !playing) {
    playing = on;
    const button = q("[data-play]");
    button.innerHTML = `${UI.icon(playing ? "pause" : "play")}<span>${playing ? "Pause" : "Play"}</span>`;
    cancelAnimationFrame(frame);  // one loop, however fast play and pause follow each other
    if (playing) { if (now >= end) now = 0; last = null; frame = requestAnimationFrame(tick); }
  }
  q("[data-play]").onclick = () => toggle();
  root.querySelectorAll("input[name=clock]").forEach((r) => (r.onchange = () => show()));
  root.querySelectorAll("input[name=size]").forEach((r) => (r.onchange = () => draw()));
  q("[data-rewind]").onclick = () => { now = 0; draw(); };
  q("[data-scrub]").oninput = (e) => { now = e.target.value / 10; draw(); };
  root.querySelectorAll("[data-param]").forEach((s) => (s.onchange = () => {
    toggle(false); now = 0;
    for (const v in loaded) delete loaded[v];  // another run
    load();
  }));

  // The menu of variants.
  const toggles = [...root.querySelectorAll("[data-variant-toggle]")];
  const count = q("[data-variant-count]");
  const choose = () => {
    for (const b of toggles) b.checked = shown.has(b.dataset.variantToggle);
    if (count) count.textContent = `${shown.size} of ${variants.length}`;
    try { localStorage.setItem(shownKey, JSON.stringify([...shown])); } catch { /* private window */ }
  };
  for (const b of toggles) {
    b.onchange = () => {
      const v = b.dataset.variantToggle;
      if (b.checked) shown.add(v); else if (shown.size > 1) shown.delete(v);
      choose();
      load();
    };
  }
  const everything = q("[data-variant-all]");
  if (everything) everything.onclick = () => { variants.forEach((v) => shown.add(v)); choose(); load(); };
  const find = q("[data-variant-find]");
  if (find) {
    find.oninput = () => root.querySelectorAll("[data-variant-row]").forEach((row) => {
      row.hidden = !row.dataset.variantRow.includes(find.value.trim().toLowerCase());
    });
  }
  const menu = q("[data-variant-menu]");
  document.addEventListener("click", (e) => { if (menu && !menu.contains(e.target)) menu.open = false; });
  choose();
  document.addEventListener("keydown", (e) => {
    if (e.target.closest("input, select, textarea, button")) return;
    if (e.code === "Space") { e.preventDefault(); toggle(); }
    if (e.key === "Home") { now = 0; draw(); }
  });
  window.addEventListener("resize", activity);
  document.addEventListener("lab:theme", show);

  load();
})();
