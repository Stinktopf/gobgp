// Scenario editor: a chain of steps, with parallel and repeat groups.
// Blocks are dragged from the palette into the chain, and steps between
// and into groups (SortableJS). The server validates the steps, computes
// the timeline and resolves the targets on a topology as the runner does.
(() => {
  const data = JSON.parse(document.getElementById("scenario-data").textContent);
  // The topologies of the preview by version; the one shown is fetched when chosen.
  const VERSIONS = JSON.parse(document.getElementById("topologies-data").textContent);
  const TOPOLOGIES = {};
  const $ = (id) => document.getElementById(id);
  const { css, el } = UI;
  const original = data.original;

  // Building blocks

  const GROUPS = { prefixes: "Prefixes", failures: "Failures", policy: "Policy", checks: "Checks", flow: "Flow" };
  // Every building block: its group, label, defaults, tooltip and fields,
  // as [key, label, type, extra]; "target" is the target picker.
  const BLOCKS = {
    announce: { group: "prefixes", label: "Announce", args: { rate: 1, for: 30 }, tip: "Origins announce prefixes for a while",
      fields: [["rate", "Rate /s", "number", { step: 0.1 }], ["for", "For s", "number"], ["router", "Routers", "router", { placeholder: "origins" }],
        ["lifetime", "Lifetime s", "number", { placeholder: 60 }], ["max_active", "Max active", "number", { placeholder: 90 }]] },
    announce_real: { group: "prefixes", label: "Real prefixes", args: { per_router: 20 },
      tip: "Routers announce prefixes their AS announces on the Internet. Needs a topology imported from CAIDA",
      fields: [["router", "Routers", "router", { placeholder: "all" }], ["per_router", "Per router", "number", { placeholder: 20 }],
        ["rate", "Rate /s", "number", { placeholder: 50 }]] },
    replay: { group: "prefixes", label: "Replay", args: { start: "2026-09-01T12:00", minutes: 30, speed: 10 },
      tip: "Prefixes of the routers appear and vanish as they did on the Internet, from the updates RIPE RIS recorded. Needs a topology imported from CAIDA",
      fields: [["start", "Start UTC", "datetime"], ["minutes", "Minutes", "number", { placeholder: 30 }],
        ["speed", "Faster ×", "number", { placeholder: 10 }], ["per_router", "Per router", "number", { placeholder: 20 }],
        ["collector", "Collector", "select", { options: ["rrc00", "rrc01", "rrc03", "rrc04", "rrc05", "rrc06", "rrc07", "rrc10", "rrc11", "rrc12", "rrc13", "rrc14", "rrc15", "rrc16", "rrc18", "rrc19", "rrc20", "rrc21", "rrc22", "rrc23", "rrc24", "rrc25", "rrc26"] }]] },
    announce_rib: { group: "prefixes", label: "Full table", args: { at: "2026-09-01T08:00" },
      tip: "Routers inject the full table their AS had on the Internet, as RIPE RIS recorded it. Needs a topology imported from CAIDA, and much memory",
      fields: [["at", "Table UTC", "datetime"], ["router", "Routers", "router", { placeholder: "all" }],
        ["at_most", "At most", "number", { placeholder: "all" }], ["prefixes", "Prefixes", "number", { placeholder: "all" }],
        ["timeout", "Timeout s", "number", { placeholder: 3600 }],
        ["collector", "Collector", "select", { options: ["rrc00", "rrc01", "rrc03", "rrc04", "rrc05", "rrc06", "rrc07", "rrc10", "rrc11", "rrc12", "rrc13", "rrc14", "rrc15", "rrc16", "rrc18", "rrc19", "rrc20", "rrc21", "rrc22", "rrc23", "rrc24", "rrc25", "rrc26"] }]] },
    withdraw_rib: { group: "prefixes", label: "Withdraw table", args: {}, tip: "Withdraw the full tables routers injected",
      fields: [["router", "Routers", "router", { placeholder: "all" }]] },
    withdraw: { group: "prefixes", label: "Withdraw", args: {}, tip: "Withdraw a share of the prefixes",
      fields: [["percent", "Percent", "number", { placeholder: 100 }], ["router", "Routers", "router", { placeholder: "origins" }]] },
    originate: { group: "prefixes", label: "Originate", args: { router: "random" }, tip: "Routers announce copies of prefixes",
      fields: [["router", "Routers", "router"], ["like", "Copies of", "router", { placeholder: "origins" }],
        ["count", "Prefixes", "number", { placeholder: 5 }], ["more_specific", "More specific", "bool"]] },
    down: { group: "failures", label: "Down", args: { link: "random" }, tip: "Take links or routers down",
      fields: [["target", "", "target"], ["mode", "Mode", "select", { options: ["session", "cut", "oneway"] }]] },
    up: { group: "failures", label: "Up", args: {}, tip: "Bring links or routers back", fields: [["target", "", "target", { everything: true }]] },
    degrade: { group: "failures", label: "Degrade", args: { link: "random", delay_ms: 50 }, tip: "Delay, jitter or loss on links",
      fields: [["target", "", "target"], ["delay_ms", "Delay ms", "number"], ["jitter_ms", "Jitter ms", "number"], ["loss_pct", "Loss %", "number", { step: 0.1 }]] },
    restart: { group: "failures", label: "Restart", args: { router: "random" }, tip: "Restart a router",
      fields: [["router", "Router", "router"], ["graceful", "Graceful", "bool"]] },
    set_preference: { group: "policy", label: "Preference", args: { router: "random", value: 300 }, tip: "Change a Local Preference",
      fields: [["router", "Router", "router"], ["neighbor", "Neighbor", "router", { placeholder: "random" }], ["value", "Local Pref", "number"]] },
    prepend: { group: "policy", label: "Prepend", args: { router: "random", times: 2 }, tip: "Make routes longer by prepending the AS",
      fields: [["router", "Routers", "router"], ["times", "Times", "number"]] },
    set_export: { group: "policy", label: "Export", args: { router: "random", allow: false }, outside: true,
      tip: "Stop or resume announcing routes to one neighbor. Outside the model: OBGP assumes export filters by the Gao-Rexford class of a neighbor",
      fields: [["router", "Router", "router"], ["neighbor", "Neighbor", "router", { placeholder: "random" }], ["allow", "Allow", "bool"]] },
    soft_reset: { group: "policy", label: "Soft reset", args: { router: "random" }, tip: "Ask the neighbors for their routes again, or send them ours",
      fields: [["router", "Routers", "router"], ["direction", "Direction", "select", { options: ["both", "in", "out"] }]] },
    expect: { group: "checks", label: "Expect", args: { router: "random" }, tip: "Check the best routes of routers",
      fields: [["router", "Routers", "router"], ["prefixes", "Prefixes", "select", { options: ["all", "none", "any"] }],
        ["via", "Via", "router", { placeholder: "any neighbor" }], ["avoid", "Avoid", "router", { placeholder: "nothing" }]] },
    wait: { group: "flow", label: "Wait", args: 10, tip: "Wait some seconds", fields: [[null, "Seconds", "number"]] },
    until_stable: { group: "flow", label: "Until stable", args: { timeout: 60 }, tip: "Wait until nothing changes", fields: [["timeout", "Timeout s", "number"]] },
    parallel: { group: "flow", label: "Parallel", args: null, tip: "Steps at the same time", fields: [] },
    repeat: { group: "flow", label: "Repeat", args: { times: 3, every: 10 }, tip: "Repeat steps",
      fields: [["times", "Times", "number"], ["every", "Every s", "number"]] },
  };

  // Model: nodes {id, kind, args, children}

  let nextId = 1;
  const isGroup = (kind) => kind === "parallel" || kind === "repeat";
  const node = (kind, args, children) => ({ id: nextId++, kind, args, children: isGroup(kind) ? children || [] : undefined });
  const fresh = (kind) => node(kind, structuredClone(BLOCKS[kind].args));
  function load(step) {
    const [kind, value] = Object.entries(step)[0];
    if (kind === "parallel") return node(kind, null, value.map(load));
    if (kind === "repeat") {
      const { steps = [], ...args } = value;
      return node(kind, args, steps.map(load));
    }
    return node(kind, kind === "wait" ? value : { ...value });
  }
  function dump(n) {
    if (n.kind === "parallel") return { parallel: n.children.map(dump) };
    if (n.kind === "repeat") return { repeat: { ...n.args, steps: n.children.map(dump) } };
    return { [n.kind]: n.args };
  }
  const root = { id: 0, kind: "root", children: data.steps.map(load) };
  let selected = null;

  function find(id, parent = root, path = []) {
    if (id === 0) return { node: root, path: [] };
    for (const [i, c] of (parent.children || []).entries()) {
      if (c.id === id) return { node: c, parent, index: i, path: [...path, i] };
      const hit = find(id, c, [...path, i]);
      if (hit) return hit;
    }
    return null;
  }

  // Topology for suggestions and the preview

  const topologySelect = $("topology");
  const network = () => TOPOLOGIES[topologySelect.value] || { routers: {}, roles: {} };
  async function loadTopology(name = topologySelect.value) {
    if (TOPOLOGIES[name] || !(name in VERSIONS)) return;
    try {
      const response = await fetch(`/topologies/${encodeURIComponent(name)}/data?v=${VERSIONS[name]}`);
      if (response.ok) TOPOLOGIES[name] = await response.json();
    } catch { /* offline: the preview stays empty */ }
  }
  function suggestions() {
    const t = network();
    const links = [];
    for (const [a, r] of Object.entries(t.routers)) for (const n of r.neighbors || []) if (a < n.name) links.push(`${a}-${n.name}`);
    const options = (values) => values.map((v) => Object.assign(document.createElement("option"), { value: v }));
    $("routers").replaceChildren(...options(["all", "random", ...Object.keys(t.roles), ...Object.keys(t.routers).sort()]));
    $("links").replaceChildren(...options(["random", ...links.sort()]));
  }

  // Rendering

  const iconEl = (name, cls = "") => { const s = el("span", `inline-flex ${cls}`); s.innerHTML = UI.icon(name); return s; };

  function summary(n) {
    const a = n.args || {};
    const target = () => a.router ?? (a.link && `link ${a.link}`) ?? (a.region && `${a.region.radius_km} km around ${a.region.around}`) ??
      (a.cut && `links out of ${a.cut.radius_km} km around ${a.cut.around}`) ?? (n.kind === "up" ? "everything" : "");
    const count = a.count > 1 ? ` ×${a.count}` : "";
    switch (n.kind) {
      case "announce": return `${a.rate}/s for ${a.for} s${a.router && a.router !== "origins" ? ` from ${a.router}` : ""}`;
      case "announce_real": return `${a.per_router ?? 20} per router${a.router && a.router !== "all" ? ` from ${a.router}` : ""}`;
      case "announce_rib": return `${a.prefixes ? `${a.prefixes} prefixes` : "full table"} of ${String(a.at).replace("T", " ")} UTC`;
      case "replay": return `${a.minutes ?? 30} min from ${String(a.start).replace("T", " ")} UTC, ${a.speed ?? 10}× faster`;
      case "withdraw": return `${a.percent ?? 100} %${a.router && a.router !== "origins" ? ` of ${a.router}` : ""}`;
      case "originate": return `${a.router}${a.more_specific ? ", more specific" : ""}`;
      case "down": return `${target()}${count}${a.mode && a.mode !== "session" ? `, ${a.mode}` : ""}`;
      case "up": return target() + count;
      case "degrade": return `${target()}${count}: ${[a.delay_ms && `${a.delay_ms} ms`, a.loss_pct && `${a.loss_pct} % loss`].filter(Boolean).join(", ")}`;
      case "restart": return `${a.router}${a.graceful ? ", graceful" : ""}`;
      case "set_preference": return `${a.router} → ${a.neighbor ?? "random"}: ${a.value}`;
      case "prepend": return `${a.router} ×${a.times}`;
      case "set_export": return `${a.router} → ${a.neighbor ?? "random"}: ${a.allow ? "allow" : "stop"}`;
      case "soft_reset": return `${a.router}, ${a.direction ?? "both"}`;
      case "expect": return [a.router, { none: "no prefixes", any: null }[a.prefixes] ?? "all prefixes", a.via && `via ${a.via}`, a.avoid && `avoid ${a.avoid}`].filter(Boolean).join(", ");
      case "wait": return `${n.args} s`;
      case "until_stable": return `at most ${a.timeout} s`;
      case "repeat": return `${a.times}× every ${a.every} s`;
      case "parallel": return `${n.children.length} at once`;
    }
    return "";
  }

  function input(value, onChange, attrs = {}) {
    const i = el("input", "input py-1 font-mono text-xs");
    const { list, tip, ...rest } = attrs;
    if (list) i.setAttribute("list", list);
    if (tip) i.dataset.tip = tip;
    Object.assign(i, rest, { value: value ?? "" });
    i.onchange = () => onChange(i.value.trim());
    return i;
  }
  const num = (v) => (v === "" ? undefined : +v.replace(",", "."));  // 0,1 as a German keyboard types it
  function setArg(n, key, value) {
    if (value === undefined || value === "") delete n.args[key]; else n.args[key] = value;
  }

  // Parameters: a number of a step offered for sweeps stands as $name in the
  // step, its value in params. Only parameters some step uses are kept.
  const params = { ...(data.params || {}) };
  const refOf = (v) => (typeof v === "string" && v.startsWith("$") ? v.slice(1) : null);
  function usedParams(nodes = root.children, out = new Set()) {
    for (const n of nodes) {
      for (const v of n.kind === "wait" ? [n.args] : Object.values(n.args || {})) if (refOf(v)) out.add(refOf(v));
      if (n.children) usedParams(n.children, out);
    }
    return out;
  }
  const liveParams = () => { const used = usedParams(); return Object.fromEntries(Object.entries(params).filter(([k]) => used.has(k))); };
  const getArg = (n, key) => (key === null ? n.args : n.args[key]);
  const putArg = (n, key, v) => { if (key === null) n.args = v ?? 0; else setArg(n, key, v); };
  // On: a parameter named after the field, its value the current one. Off: the value back in the step.
  function toggleParam(n, key, fallback) {
    const ref = refOf(getArg(n, key));
    if (ref) {
      putArg(n, key, params[ref]);
    } else {
      let name = (key || "seconds").replace(/[^a-z0-9_]/g, "_"), i = 2;
      while (name in params && usedParams().has(name)) name = `${(key || "seconds")}_${i++}`;
      params[name] = +(getArg(n, key) ?? fallback ?? 0);
      putArg(n, key, `$${name}`);
    }
    for (const k of Object.keys(params)) if (!usedParams().has(k)) delete params[k];
  }
  function renameParam(from, to) {
    if (!/^[a-z][a-z0-9_]*$/.test(to) || to === from || to in params) return false;
    params[to] = params[from];
    delete params[from];
    const walk = (nodes) => nodes.forEach((n) => {
      if (n.kind === "wait") { if (refOf(n.args) === from) n.args = `$${to}`; }
      else for (const [k, v] of Object.entries(n.args || {})) if (refOf(v) === from) n.args[k] = `$${to}`;
      if (n.children) walk(n.children);
    });
    walk(root.children);
    return true;
  }

  function targetField(n, everything) {
    const a = n.args;
    const kinds = ["router", "link", "region", "cut"];
    const current = kinds.find((k) => a[k] != null) || (everything ? "all" : "router");
    const wrap = el("div", "col-span-full grid grid-cols-[8rem_1fr_4.5rem] gap-2");
    const select = el("select", "input py-1 text-xs");
    select.setAttribute("aria-label", "Target");
    const names = { all: "Everything down", router: "Router", link: "Link", region: "Region", cut: "Cut around" };
    for (const k of [...(everything ? ["all"] : []), ...kinds]) select.append(Object.assign(el("option", "", names[k]), { value: k, selected: k === current }));
    select.onchange = () => {
      for (const k of kinds) delete a[k];
      delete a.count;
      if (select.value === "router" || select.value === "link") a[select.value] = "random";
      if (select.value === "region" || select.value === "cut") a[select.value] = { around: Object.keys(network().routers)[0] || "", radius_km: 300 };
      changed();
    };
    wrap.append(select);
    if (current === "router" || current === "link") {
      wrap.append(input(a[current], (v) => { a[current] = v; edited(n); }, { list: current === "router" ? "routers" : "links" }));
      wrap.append(input(a.count, (v) => { setArg(n, "count", num(v)); edited(n); }, { type: "number", min: 1, placeholder: "×1", tip: "Random choices" }));
    } else if (current === "region" || current === "cut") {
      wrap.append(input(a[current].around, (v) => { a[current].around = v; edited(n); }, { list: "routers" }));
      wrap.append(input(a[current].radius_km, (v) => { a[current].radius_km = num(v); edited(n); }, { type: "number", min: 1, tip: "Radius km" }));
    } else {
      wrap.append(el("span", "muted col-span-2 self-center text-xs", "Brings back all failures"));
    }
    return wrap;
  }

  function fields(n) {
    const grid = el("div", "grid grid-cols-2 gap-2 sm:grid-cols-3");
    for (const [key, label, type, extra = {}] of BLOCKS[n.kind].fields) {
      if (type === "target") { grid.append(targetField(n, extra.everything)); continue; }
      const wrap = el("label", "block");
      const head = el("span", "flex items-center gap-1");
      head.append(el("span", "label", label));
      wrap.append(head);
      const ref = type === "number" ? refOf(getArg(n, key)) : null;
      const value = ref ? params[ref] : key === null ? n.args : n.args[key];
      if (type === "number") {
        // Offered for sweeps: the experiment can run the scenario once for each of several values.
        const sweep = el("button", `ml-auto rounded px-1 text-[10px] font-medium ${ref ? "sweep-badge" : "text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"}`, "sweep");
        Object.assign(sweep, { type: "button" });
        sweep.dataset.tip = ref ? "Offered for sweeps as a parameter. Click to keep the number in the step" : "Offer this number for sweeps: an experiment can run the scenario once for each of several values";
        sweep.setAttribute("aria-pressed", !!ref);
        sweep.onclick = (e) => { e.preventDefault(); toggleParam(n, key, extra.placeholder); edited(n); render(); };
        head.append(sweep);
      }
      let control;
      if (type === "bool") {
        control = el("input", "mt-2 block accent-uoft-700 dark:accent-uoft-400");
        Object.assign(control, { type: "checkbox", checked: !!value });
        control.onchange = () => { setArg(n, key, control.checked || undefined); edited(n); };
      } else if (type === "select") {
        control = el("select", "input py-1 text-xs");
        for (const o of extra.options) control.append(Object.assign(el("option", "", o), { value: o, selected: (value ?? extra.options[0]) === o }));
        control.onchange = () => { setArg(n, key, control.value === extra.options[0] ? undefined : control.value); edited(n); };
      } else {
        // Decimals as text: a number field shows them in the browser's language, 0,1 in German.
        const number = extra.step < 1 ? { inputMode: "decimal", pattern: "[0-9]*[.,]?[0-9]+" } : { type: "number", step: extra.step || 1, min: 0 };
        const attrs = { number, datetime: { type: "datetime-local" } }[type] || { list: "routers" };
        control = input(value, (v) => {
          const parsed = type === "number" ? num(v) : v;
          if (ref) params[ref] = parsed ?? 0;  // the value of the parameter, the step keeps $name
          else if (key === null) n.args = parsed ?? 0; else setArg(n, key, parsed);
          edited(n);
        }, { ...attrs, placeholder: extra.placeholder ?? "" });
      }
      if (ref) control.classList.add("sweep-field");
      wrap.append(control);
      if (ref) {
        // The name of the parameter, as experiments list it.
        const name = input(ref, (v) => { if (!renameParam(ref, v)) name.value = ref; else { edited(n); render(); } },
          { tip: "Name of the parameter, as experiments offer it for sweeps" });
        name.className = "input sweep-field mt-1 py-0.5 font-mono text-[11px] text-violet-800 dark:text-violet-200";
        name.value = ref;
        wrap.append(name);
      }
      grid.append(wrap);
    }
    return grid;
  }

  let preview = { timeline: [], targets: {} };
  const pathOf = (n) => find(n.id)?.path.join(".");
  const targetsOf = (n) => preview.targets[pathOf(n)];
  const timingOf = (n) => preview.timeline.find((r) => r.path.join(".") === pathOf(n));

  function card(n, number) {
    const isSelected = n.id === selected;
    const c = el("div", `step rounded-lg bg-white ring-1 transition dark:bg-slate-900 ${isSelected ? "ring-uoft-500 shadow-[var(--glow)]" : "ring-slate-900/10 hover:ring-slate-900/25 dark:ring-white/10 dark:hover:ring-white/25"}`);
    c.dataset.id = n.id;
    const head = el("div", "flex cursor-pointer items-center gap-2 rounded-lg py-1.5 pr-2 pl-1 focus-visible:outline-2 focus-visible:outline-uoft-500");
    head.tabIndex = 0;
    head.setAttribute("role", "button");
    head.setAttribute("aria-expanded", isSelected);
    const grip = iconEl("grip", "grip cursor-grab px-1 text-slate-300 active:cursor-grabbing dark:text-slate-600");
    grip.dataset.tip = "Drag";
    head.append(grip, el("span", "w-6 text-right text-xs text-slate-400 tabular-nums", number));
    head.append(iconEl(n.kind, "text-slate-500 dark:text-slate-400"), el("span", "text-sm font-medium", BLOCKS[n.kind].label));
    if (BLOCKS[n.kind].outside) {
      const tag = el("span", "tag shrink-0", "outside model");
      tag.dataset.tip = "OBGP assumes export filters by the Gao-Rexford class of a neighbor";
      head.append(tag);
    }
    head.append(el("span", "summary muted min-w-0 flex-1 truncate font-mono text-xs", summary(n)));
    // Numbers offered for sweeps, visible while the step is closed.
    const swept = (n.kind === "wait" ? [n.args] : Object.values(n.args || {})).map(refOf).filter(Boolean);
    if (swept.length) {
      const badge = el("span", "sweep-badge", `⇄ ${swept.join(", ")}`);
      badge.dataset.tip = "Offered for sweeps: an experiment can run this scenario once for each of several values";
      head.append(badge);
    }
    const t = timingOf(n);
    head.append(el("span", "timing text-xs text-slate-400 tabular-nums", t ? `${Math.round(t.start)} s` : ""));
    const remove = el("button", "rounded p-0.5 text-slate-300 hover:bg-rose-50 hover:text-rose-600 dark:text-slate-600 dark:hover:bg-rose-950");
    remove.innerHTML = UI.icon("close");
    remove.setAttribute("aria-label", "Remove");
    remove.dataset.tip = "Remove";
    remove.onclick = (e) => { e.stopPropagation(); removeStep(n.id); };
    head.append(remove);
    head.onclick = () => {
      selected = isSelected ? null : n.id;
      render();
      $("steps").querySelector(`.step[data-id="${n.id}"] [role=button]`)?.focus();
    };
    head.onkeydown = (e) => { if ((e.key === "Enter" || e.key === " ") && e.target === head) { e.preventDefault(); head.onclick(); } };
    c.append(head);
    if (isSelected && BLOCKS[n.kind].fields.length) {
      const body = el("div", "border-t border-slate-900/5 px-3 pt-2 pb-3 dark:border-white/10");
      body.append(fields(n));
      body.append(el("p", "target-error error mt-2 text-xs", targetsOf(n)?.error || ""));
      c.append(body);
    }
    if (n.children) c.append(list(n, `${number}.`));
    return c;
  }

  // A list of steps; an empty list shows where to drop.
  function list(parent, prefix = "") {
    const box = el("div", parent === root
      ? "steps min-h-24 space-y-2"
      : "steps mr-2 mb-2 ml-8 min-h-10 space-y-1.5 rounded-md border-l-2 border-slate-200 py-1 pl-2 dark:border-slate-700");
    box.dataset.parent = parent.id;
    box.dataset.empty = parent === root ? "Drag blocks here" : "Drag steps into the group";
    parent.children.forEach((c, i) => box.append(card(c, `${prefix}${i + 1}`)));
    return box;
  }

  const sortables = [];
  function render() {
    sortables.splice(0).forEach((s) => s.destroy());
    $("steps").replaceChildren(list(root));
    for (const box of $("steps").querySelectorAll(".steps")) {
      sortables.push(Sortable.create(box, {
        group: "steps", handle: ".grip", animation: 150, fallbackOnBody: true, swapThreshold: 0.6, emptyInsertThreshold: 24,
        ghostClass: "sortable-ghost", onAdd: dropped, onUpdate: dropped,
      }));
    }
    renderTimeline();
    highlight();
  }

  // A block from the palette, or a step from any list, landed in a list.
  function dropped(e) {
    const to = find(+e.to.dataset.parent).node;
    let moving;
    if (e.item.dataset.kind) {  // from the palette
      moving = fresh(e.item.dataset.kind);
      e.item.remove();
    } else {
      const from = find(+e.from.dataset.parent).node;
      moving = from.children.splice(e.oldIndex, 1)[0];
    }
    to.children.splice(e.newIndex, 0, moving);
    selected = moving.id;
    changed();
  }

  // Palette: drag a block to its place, or click to add it after the selection.

  function palette() {
    const box = $("palette");
    for (const [key, label] of Object.entries(GROUPS)) {
      const group = el("div", "flex items-center gap-2");
      group.append(el("span", "label w-16 shrink-0", label));
      const blocks = el("div", "flex flex-wrap gap-1.5");
      for (const [kind, b] of Object.entries(BLOCKS).filter(([, b]) => b.group === key)) {
        const chip = el("button", `btn cursor-grab px-2 py-1 text-xs active:cursor-grabbing ${b.outside ? "border-dashed" : ""}`);
        chip.type = "button";
        chip.dataset.kind = kind;
        chip.dataset.tip = BLOCKS[kind].tip;
        chip.append(iconEl(kind, "text-slate-500 dark:text-slate-400"), b.label);
        chip.onclick = () => add(kind);
        blocks.append(chip);
      }
      group.append(blocks);
      box.append(group);
      Sortable.create(blocks, { group: { name: "steps", pull: "clone", put: false }, sort: false, animation: 150 });
    }
  }

  function add(kind) {
    const n = fresh(kind);
    const hit = selected && find(selected);
    if (hit && hit.node.children) hit.node.children.push(n);   // into the selected group
    else if (hit) hit.parent.children.splice(hit.index + 1, 0, n); // after the selected step
    else root.children.push(n);
    selected = n.id;
    changed();
  }

  // Timeline: one row per step, bars for durations, dots for moments

  function renderTimeline() {
    const box = $("timeline");
    const rows = preview.timeline;
    const end = Math.max(1, ...rows.map((r) => r.estimate ?? r.end));
    $("duration").textContent = rows.length ? `≈ ${fmt(preview.duration_s)}` : "";
    box.replaceChildren();
    const lane = el("div", "relative");
    lane.style.height = `${rows.length * 9 + 18}px`;
    const x = (t) => `${(100 * t) / end}%`;
    const step = niceStep(end);
    for (let t = 0; t <= end; t += step) {
      const align = t === 0 ? "" : t + step > end ? "-translate-x-full" : "-translate-x-1/2";
      const tick = el("span", `absolute bottom-0 ${align} text-[10px] whitespace-nowrap text-slate-400 tabular-nums`, `${t} s`);
      tick.style.left = x(t);
      const line = el("span", "absolute top-0 bottom-4 w-px bg-slate-100 dark:bg-slate-800");
      line.style.left = x(t);
      lane.append(line, tick);
    }
    rows.forEach((r, i) => {
      const n = nodeAt(r.path);
      const on = n?.id === selected;
      const top = `${i * 9}px`;
      if (r.estimate != null) {
        const est = el("span", "absolute h-1.5 rounded-sm border border-dashed border-slate-300 dark:border-slate-600");
        Object.assign(est.style, { left: x(r.start), width: x(r.estimate - r.start), top });
        lane.append(est);
      }
      const width = r.end - r.start;
      const bar = el("button", `absolute h-1.5 cursor-pointer rounded-sm ${on ? "bg-uoft-600 dark:bg-uoft-300" : "bg-slate-400 hover:bg-slate-500 dark:bg-slate-500"}`);
      bar.type = "button";
      bar.setAttribute("aria-label", `${BLOCKS[r.kind].label} at ${fmt(r.start)}`);
      Object.assign(bar.style, { left: x(r.start), width: width > 0 ? x(width) : "6px", top, transform: width > 0 ? "" : "translateX(-3px)" });
      bar.dataset.tip = `${BLOCKS[r.kind].label} at ${fmt(r.start)}`;
      bar.onclick = () => { if (n) { selected = n.id; render(); } };
      lane.append(bar);
    });
    box.append(lane);
  }
  const nodeAt = (path) => path.reduce((n, i) => n?.children?.[i], root);
  const niceStep = (end) => [1, 2, 5, 10, 15, 30, 60, 120, 300, 600].find((s) => end / s <= 8) || 900;
  function fmt(s) {
    s = Math.round(s);
    return s >= 60 ? `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, "0")} s` : `${s} s`;
  }

  function removeStep(id) {
    const hit = find(id);
    hit.parent.children.splice(hit.index, 1);
    if (selected === id) selected = null;
    changed();
  }

  // Delete removes the selected step, as in the topology editor, unless typing or in a dialog.
  document.addEventListener("keydown", (e) => {
    if (!["Delete", "Backspace"].includes(e.key) || !selected || !find(selected)) return;
    if (e.target.closest("input, textarea, select, button, [contenteditable]") || document.querySelector("dialog[open]")) return;
    e.preventDefault();
    removeStep(selected);
  });

  // Topology preview: what the selected step acts on

  let cy = null;
  function drawTopology() {
    cy?.destroy();
    cy = Graph.view($("preview"), network(), { styles: [
      { selector: "node.hit", style: { "background-color": css("--graph-accent"), "underlay-color": css("--graph-accent"),
        "underlay-opacity": 0.2, "underlay-padding": Graph.px(() => cy, 6), "underlay-shape": "ellipse" } },
      { selector: "edge.hit", style: { "line-color": css("--graph-accent"), width: Graph.px(() => cy, 4) } },
      { selector: "node.dim, edge.dim", style: { opacity: 0.4 } },
    ] });
    highlight();
  }

  function highlight() {
    if (!cy) return;
    cy.elements().removeClass("hit dim");
    const n = selected && find(selected)?.node;
    const hit = n && targetsOf(n);
    $("targets").textContent = !n ? "Select a step to see what it acts on." : !hit ? "Acts on no router or link." : hit.error ? hit.error :
      [hit.routers.join(", "), hit.links.map((l) => l.join("–")).join(", ")].filter(Boolean).join(" · ");
    $("targets").classList.toggle("error", !!hit?.error);
    if (!hit || hit.error) return;
    cy.elements().addClass("dim");
    for (const r of hit.routers) cy.getElementById(r).removeClass("dim").addClass("hit");
    for (const [a, b] of hit.links) cy.getElementById([a, b].sort().join("|")).removeClass("dim").addClass("hit").connectedNodes().removeClass("dim");
  }

  // Server: validation, timeline, targets

  let pending = null, requests = 0;
  function refresh() {
    clearTimeout(pending);
    pending = setTimeout(async () => {
      const request = ++requests;
      const { data: result } = await UI.post("/scenarios/preview",
        { steps: root.children.map(dump), params: liveParams(), topology: topologySelect.value, seed: $("seed").value, run: $("run").value });
      if (request !== requests) return;  // a newer preview is on its way
      const problems = $("problems");
      problems.replaceChildren(...(result.problems || []).map((p) => el("li", "", p)));
      problems.hidden = !result.problems?.length;
      preview = result.problems?.length ? { timeline: [], targets: {} } : result;
      updatePreview();
    }, 150);
  }

  // Timings, target errors, timeline and preview, without touching the fields.
  function updatePreview() {
    for (const c of $("steps").querySelectorAll(".step")) {
      const n = find(+c.dataset.id)?.node;
      if (!n) continue;
      const t = timingOf(n);
      c.querySelector(":scope > div .timing").textContent = t ? `${Math.round(t.start)} s` : "";
      const error = c.querySelector(":scope > div + div .target-error");
      if (error) error.textContent = targetsOf(n)?.error || "";
    }
    renderTimeline();
    highlight();
  }

  // A field changed: the summary of its card, then the preview.
  function edited(n) {
    const card = $("steps").querySelector(`.step[data-id="${n.id}"] .summary`);
    if (card) card.textContent = summary(n);
    markDirty();
    refresh();
  }

  // Unsaved means: different from what was loaded or saved last.
  const state = () => JSON.stringify({ name: $("name").value.trim(), description: $("description").value.trim(), params: liveParams(), steps: root.children.map(dump) });
  let editor = null;  // made once the scenario is drawn
  const markDirty = () => editor?.mark();

  function changed() {
    markDirty();
    render();
    refresh();
  }

  $("name").oninput = $("description").oninput = markDirty;
  topologySelect.onchange = async () => { await loadTopology(); suggestions(); drawTopology(); refresh(); };
  $("seed").onchange = $("run").onchange = refresh;
  document.addEventListener("lab:theme", drawTopology);

  palette();
  render();
  loadTopology().then(() => { suggestions(); drawTopology(); highlight(); });
  refresh();
  editor = UI.editor({
    kind: "scenarios", original, used: window.SCENARIO_USED, state,
    body: () => ({ description: $("description").value, params: liveParams(), steps: root.children.map(dump) }),
    // A state of the undo: the steps again, none selected.
    restore: (text) => {
      const t = JSON.parse(text);
      $("name").value = t.name;
      $("description").value = t.description;
      root.children = t.steps.map(load);
      for (const k of Object.keys(params)) delete params[k];
      Object.assign(params, t.params);
      selected = null;
      render();
      refresh();
    },
  });
})();
