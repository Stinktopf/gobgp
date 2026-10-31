// Simulation: one finding of the simulator, told in key moments. The mode
// with the problem is drawn large, the one to compare small beside it, at
// the same point of the run: after the same events. A step is a message
// between two routers or an event from outside. Routers sit on a circle with
// an arrow to their next hop, a loop drawn red, the routers of the problem
// ringed. Under them every router's table: what goes in and out per
// neighbor. Every step stays reachable on the timeline.
(() => {
  const root = document.getElementById("sim");
  if (!root) return;
  const example = JSON.parse(document.getElementById("sim-example").textContent);
  const inst = example.instance, finding = example.finding;
  const n = inst.routers, origin = inst.origin ?? 0;
  // The modes that show the problem on this network, each with the routers it affects.
  const perMode = JSON.parse(root.dataset.modes), affected = new Set(Object.keys(perMode));
  const hitOf = (mode) => new Set(perMode[mode]?.routers || []);
  // Units of a hundredth: the circle has radius 100.
  const at = (i) => [100 * Math.cos((2 * Math.PI * i) / n - Math.PI / 2), 100 * Math.sin((2 * Math.PI * i) / n - Math.PI / 2)];
  const counter = root.querySelector("[data-counter]");
  const timeline = root.querySelector("[data-timeline]");
  const traces = {}, chosen = {};
  let step = 0, timer = null;
  const NS = "http://www.w3.org/2000/svg";
  const el = (name, attrs) => { const e = document.createElementNS(NS, name); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); return e; };
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const dark = () => document.documentElement.dataset.theme === "dark";  // as base.html sets it
  const palette = () => dark()
    ? { route: "#93b0e0", text: "#0f172a", none: "#1e293b", noneText: "#cbd5e1", waits: "#a78bfa", problem: "#fb7185", message: "#94a3b8", link: "#334155", step: "#1e293b", ring: "#93b0e0", page: "#0f172a" }
    : { route: "#1e3765", text: "#ffffff", none: "#e2e8f0", noneText: "#1e293b", waits: "#a78bfa", problem: "#e11d48", message: "#64748b", link: "#cbd5e1", step: "#e2e8f0", ring: "#1e3765", page: "#ffffff" };

  // AS numbers to routers, as the simulator assigns them: AS index i has the
  // number 65001 + i unless asns gives it, a router the AS index inst.as gives,
  // or its own. An AS of several routers stays an AS.
  const asIndex = (r) => (inst.as && inst.as.length ? inst.as[r] : r);
  const asNumber = (a) => (inst.asns && a < inst.asns.length ? inst.asns[a] : 65001 + a);
  const members = {};
  for (let r = 0; r < n; r++) (members[asNumber(asIndex(r))] ||= []).push(r);
  const hop = (asn) => (members[asn] && members[asn].length === 1 ? String(members[asn][0]) : `AS ${asn}`);
  const poison = inst.origin_poison || [];
  const route = (p) => {
    if (p === null || p === undefined) return "no route";
    if (!p.length) return "own prefix";
    // The origin puts the ASes it poisons before its own: they stand in the path, not on it.
    const k = poison.length;
    const poisoned = k && p.length > k && poison.every((a, j) => p[p.length - 1 - k + j] === a);
    const passed = poisoned ? [...p.slice(0, p.length - 1 - k), p[p.length - 1]] : p;
    return "via " + passed.map(hop).join("→") + (poisoned ? `, poisons AS ${poison.join(", ")}` : "");
  };
  const routers = (list) => (list.length === 1 ? `router ${list[0]}` : `routers ${list.slice(0, -1).join(", ")} and ${list[list.length - 1]}`);
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const has = (list, p) => list.some((q) => same(q, p));

  function event(e) {
    // Everything here goes into the page as HTML, the simulator's numbers too.
    const a = esc(e.from ?? 0), b = esc(e.to ?? 0), v = esc(e.value ?? ""), on = e.value ? "starts" : "stops";
    return {
      withdraw: "the origin withdraws the prefix",
      announce: "the origin announces the prefix again",
      down: `link ${a}–${b} fails`,
      up: `link ${a}–${b} comes back`,
      prepend: `router ${a} prepends ${v}× towards ${b}`,
      "prepend-all": `router ${a} prepends ${v}× towards all`,
      "local-pref": `router ${b} sets local preference ${e.value ? v : "back"} for routes from ${a}`,
      igp: `IGP cost of link ${a}–${b} becomes ${v}`,
      "deny-export": `router ${a} ${on} filtering what it sends ${b}`,
      "deny-import": `router ${b} ${on} rejecting what ${a} sends`,
    }[e.kind] || esc(e.kind);
  }

  // What goes wrong, from the run of the finding's mode, once per run: the
  // step it shows at and one sentence.
  function analyse(t) {
    const hit = hitOf(t.mode);
    const steps = t.steps, end = steps.length, last = steps[end - 1];
    if (!end) return { at: 0, text: finding.detail };
    const had = new Array(n).fill(false);
    const lost = steps.map((s) => s.routers.map((r, i) => { const gone = had[i] && r.best === null; if (r.best !== null) had[i] = true; return gone; }));
    const span = (test) => {
      const first = steps.findIndex(test);
      if (first < 0) return null;
      let k = first;
      while (k + 1 < end && test(steps[k + 1], k + 1)) k++;
      return [first + 1, k + 1];
    };
    const until = ([a, b]) => (b > a ? ` to ${b}` : "");
    const bgp = example.results && example.results.bgp;
    switch (finding.kind) {
      case "transient-loop": {
        const r = span((s) => s.loop && s.loop.length);
        if (r) return { at: r[0], text: `From step ${r[0]}${until(r)}, ${routers(steps[r[0] - 1].loop)} forward to each other, so packets circle.` };
        break;
      }
      case "transient-blocked": {
        const r = span((s, k) => s.routers.some((x, i) => x.waits && lost[k ?? steps.indexOf(s)][i]));
        if (r) {
          const who = steps[r[0] - 1].routers.map((x, i) => (x.waits ? i : -1)).filter((i) => i >= 0);
          return { at: r[0], text: `From step ${r[0]}${until(r)}, ${routers(who)} wait${who.length > 1 ? "" : "s"} for a route refresh without a route, so packets are dropped.` };
        }
        break;
      }
      case "transient-hole": {
        const k = lost.findIndex((row) => row.some((g, i) => g && last.routers[i].best !== null));
        if (k >= 0) {
          const who = lost[k].map((g, i) => (g && last.routers[i].best !== null ? i : -1)).filter((i) => i >= 0);
          const back = steps.findIndex((s, j) => j > k && who.every((i) => s.routers[i].best !== null));
          return { at: k + 1, text: `At step ${k + 1}, ${routers(who)} lose${who.length > 1 ? "" : "s"} the route${back > 0 ? ` until step ${back + 1}` : ""}, so packets are dropped meanwhile.` };
        }
        break;
      }
      case "loop":
        return { at: end, text: `At rest ${routers(last.loop || [...hit])} forward to each other, so packets circle forever.` };
      case "unreachable": {
        const who = [...hit];
        const theirs = bgp ? ` BGP reaches it ${who.map((i) => route(bgp.best[i])).join(", ")}.` : "";
        return { at: end, text: `At rest ${routers(who)} ${who.length > 1 ? "have" : "has"} no route to the prefix.${theirs}` };
      }
      case "black-hole":
        return { at: end, text: `At rest packets from ${routers([...hit])} reach a router without a route.` };
      case "leaked":
        return { at: end, text: `At rest ${routers([...hit])} forward${hit.size > 1 ? "" : "s"} on a path that is not valley-free.` };
      case "no-convergence": {
        const changes = new Array(n).fill(0);
        for (let k = Math.max(1, Math.floor(end / 2)); k < end; k++) steps[k].routers.forEach((r, i) => { if (!same(r.best, steps[k - 1].routers[i].best)) changes[i]++; });
        const busy = changes.map((c, i) => [c, i]).filter(([c]) => c > 0).sort((a, b) => b[0] - a[0]).slice(0, 3).map(([, i]) => i);
        return { at: end, text: `After ${end} steps the routes still change${busy.length ? `, at ${routers(busy)} most often` : ""}.` };
      }
    }
    return { at: end, text: finding.detail };
  }

  // Why the problem happens, in one or two sentences from the run's own
  // state at the step it shows: what the routers around it hold and offer,
  // and the policies of the network on the way. Facts only, no guesses.
  // A router's neighbors over its links, in order.
  const neighbors = (i) => [...new Set(inst.links.flatMap(([a, b]) => (a === i ? [b] : b === i ? [a] : [])))].sort((a, b) => a - b);
  function why(t) {
    if (!t.problem || !t.problem.at) return "";
    const s = t.steps[t.problem.at - 1], bgp = example.results && example.results.bgp;
    // Per router without a route: what each neighbor with one offers it, and what stops it. BGP's offer beside.
    const lacking = (who) => who.map((h) => {
      const near = neighbors(h).filter((x) => s.routers[x].best !== null && s.routers[x].next_hop !== h);
      if (!near.length) return `No neighbor of router ${h} has a route.`;
      return near.map((x) => {
        // From the run itself: what router x sends router h, or why not, and what h makes of it.
        const sent = (s.routers[x].out || []).find((o) => o.to === h), got = (s.routers[h].in || []).find((o) => o.from === x);
        const theirs = bgp && bgp.exported && bgp.exported[x] && !same(bgp.exported[x], s.routers[x].exported) ? ` BGP offers ${route(bgp.exported[x])}.` : "";
        if (sent && !sent.path) return `Router ${x} sends router ${h} nothing: ${esc(sent.not)}.${theirs}`;
        const fate = got && got.fate !== "none" ? got.fate : "";
        const told = { "set aside": "sets it aside", filtered: "filters it on import", loop: "rejects it as a loop", pruned: "has pruned it", dropped: "does not keep it" }[fate];
        return `Router ${x} sends router ${h} ${route(sent ? sent.path : s.routers[x].exported)}, which router ${h} ${told || "does not admit"}.${theirs}`;
      }).join(" ");
    }).join(" ");
    switch (finding.kind) {
      case "unreachable": case "transient-hole": case "black-hole":
        return lacking([...hitOf(t.mode)].filter((h) => s.routers[h].best === null).slice(0, 2));
      case "transient-blocked": {
        const w = s.routers.findIndex((r) => r.waits && r.best === null);
        if (w < 0) return "";
        const aside = s.routers[w].set_aside;
        const offered = t.steps.slice(0, t.problem.at - 1).map((x) => x.routers[w].exported).filter((p) => p !== null).pop();
        return aside.length ? `Router ${w} lost its route and sets ${aside.map(route).join(" and ")} aside, as OBGP only admits a path shorter than the one it offered${offered ? ` (${route(offered)})` : ""}. It waits for a refresh.`
          : `Router ${w} lost its route and has no other. It waits for a refresh.`;
      }
      case "transient-loop": case "loop": {
        const loop = s.loop && s.loop.length ? s.loop : [...hitOf(t.mode)];
        if (loop.length < 2) return "";
        // Inside one AS the way to the BGP next hop runs over the IGP, through another router of the loop.
        const inside = loop.every((i) => asIndex(i) === asIndex(loop[0]));
        return inside ? `${cap(routers(loop))} hold paths ${loop.map((i) => route(s.routers[i].best)).filter((x, k, all) => all.indexOf(x) === k).join(" and ")}, and inside their AS each reaches that next hop through the other, so packets go round.`
          : `${cap(loop.map((i) => `router ${i} forwards to router ${s.routers[i].next_hop}`).join(" and "))}: each still holds a path through the other, so packets go round.`;
      }
      case "no-convergence": {
        const prefs = (inst.sessions || []).filter((x) => x.local_pref).map((x) => `router ${x.to ?? 0} prefers routes from router ${x.from ?? 0}`);
        return prefs.length ? `${cap(prefs.join(", "))}, so each takes its neighbor's path, which then changes again.` : "";
      }
    }
    return "";
  }

  function arrow(svg, side, a, b, color, marker, dashed, width, shift = 0) {
    const [x1, y1] = at(a), [x2, y2] = at(b);
    // The line stops where the head begins, so that it does not show through the head's tip.
    const k = 17, head = 5 * width, dx = x2 - x1, dy = y2 - y1, d = Math.hypot(dx, dy);
    const ox = (-dy / d) * shift, oy = (dx / d) * shift;  // beside the link, so that both directions show
    svg.append(el("line", { x1: x1 + (dx / d) * k + ox, y1: y1 + (dy / d) * k + oy, x2: x2 - (dx / d) * (k + head) + ox, y2: y2 - (dy / d) * (k + head) + oy,
      stroke: color, "stroke-width": width, "stroke-dasharray": dashed ? "5 3.5" : "", "marker-end": `url(#${side}-${marker})` }));
  }

  // A RIB as show bgp lists it, in words: a row per path a router holds, the
  // best first, then the admitted and those set aside, and what it offers.
  // One router at a step as a small table, a row per neighbor: what it
  // receives from it, what the router takes of that, and what it sends it
  // or why not. Under it what the router offers: OBGP its worst admitted
  // path, BGP its best. A cell the step changed is shaded.
  const taken = {
    best: "font-semibold text-uoft-700 dark:text-uoft-300", admitted: "", "set aside": "text-violet-700 dark:text-violet-300",
    filtered: "text-rose-700 dark:text-rose-300", loop: "text-rose-700 dark:text-rose-300", pruned: "text-rose-700 dark:text-rose-300", dropped: "muted",
  };
  const path = (p) => (p === null || p === undefined ? '<span class="muted">nothing</span>' : `<span class="font-mono">${p.length ? esc(p.join(" ")) : "own prefix"}</span>`);
  function ribRows(t, shown, i, focused) {
    const r = t.steps[shown - 1].routers[i];
    const was = shown > 1 ? t.steps[shown - 2].routers[i] : null;
    const obgp = t.mode !== "bgp", pn = t.mode.endsWith("-pn");
    // A path it takes in is offered when a neighbor gets it, behind the router's own AS:
    // with tables per neighbor each neighbor may get another one.
    const offered = (x) => ["best", "admitted"].includes(x.fate) && r.out.some((o) => {
      if (!o.path) return false;
      // Inside its AS the path goes on unchanged.
      if (asIndex(o.to) === asIndex(i) && same(o.path, x.path)) return true;
      // Else a neighbor gets the path behind the router's own AS, once or prepended: nothing else before it.
      if (o.path.length <= x.path.length) return false;
      const lead = o.path.slice(0, o.path.length - x.path.length);
      return same(o.path.slice(lead.length), x.path) && lead.every((a) => a === lead[0]);
    });
    if (!r.in || !r.out) return `<section class="rounded-lg border border-slate-900/10 p-2.5 dark:border-white/10"><b>Router ${i}</b><p class="muted text-xs">Not recorded in this replay.</p></section>`;
    const of = (list, side, j) => (list || []).filter((x) => x[side] === j);
    const differs = (a, b) => JSON.stringify(a) !== JSON.stringify(b);
    // A cell the step changed: a thin bar in the accent on its left.
    const shade = (now, then) => (was && differs(now, then) ? "shadow-[inset_2px_0_0] shadow-uoft-500 pl-1.5" : "");
    // Its neighbors over links, and the iBGP peers the trace names beside them.
    const peers = [...new Set([...neighbors(i), ...r.in.map((x) => x.from), ...r.out.map((x) => x.to)])].sort((a, b) => a - b);
    const rows = peers.map((j) => {
      const got = of(r.in, "from", j), sent = of(r.out, "to", j);
      const gotThen = was ? of(was.in, "from", j) : got, sentThen = was ? of(was.out, "to", j) : sent;
      const receives = got.length && got[0].fate !== "none" ? got.map((x) => path(x.path)).join("<br>") : '<span class="muted">nothing</span>';
      const takes = got.filter((x) => x.fate !== "none").map((x) => `<span class="${taken[x.fate] || ""}">${x.fate}</span>${
        offered(x) ? `<span class="muted" data-tip="${pn ? "Each neighbor gets the worst path admitted in its own table" : obgp ? "OBGP offers its worst admitted path" : "BGP offers its best path"}"> · offered</span>` : ""}`).join("<br>") || '<span class="muted">–</span>';
      const sends = sent.map((x) => (x.path ? path(x.path) : `<span class="muted">${esc(x.not || "nothing")}</span>`)).join("<br>") || '<span class="muted">–</span>';
      const cell = "py-1 pr-3 align-top";
      return `<tr class="border-t border-slate-900/5 dark:border-white/5">
        <td class="${cell} tabular-nums">${j}</td>
        <td class="${cell} ${shade(got, gotThen)}">${receives}</td>
        <td class="${cell} whitespace-nowrap ${shade(got, gotThen)}">${takes}</td>
        <td class="py-1 align-top ${shade(sent, sentThen)}">${sends}</td></tr>`;
    }).join("");
    const rule = r.exported === null || r.exported.length === 0 ? "" : obgp ? ", its worst admitted path" : ", its best path";
    const offerLine = pn ? '<span class="muted">Offers each neighbor the worst path admitted in that neighbor\'s own table, see Sends</span>'
      : `<span class="muted">Offers</span> ${path(r.exported)}<span class="muted">${rule}</span>`;
    return `<section class="rounded-lg border border-slate-900/10 p-2.5 dark:border-white/10 ${focused ? "bg-uoft-50 dark:bg-uoft-900/40" : ""}">
      <div class="mb-1 flex flex-wrap items-baseline gap-x-2 text-sm"><button type="button" class="hit font-semibold" data-router-pick="${i}">Router ${i}</button>
        ${i === origin ? '<span class="muted text-xs">origin</span>' : ""}
        ${r.waits ? '<span class="text-xs text-violet-700 dark:text-violet-300">waits for a refresh</span>' : ""}</div>
      <table class="w-full table-fixed text-xs"><colgroup><col class="w-16"><col><col class="w-28"><col></colgroup><thead class="muted"><tr><th class="pr-3 pb-1 text-left font-normal">Neighbor</th>
        <th class="pr-3 pb-1 text-left font-normal">Receives</th><th class="pr-3 pb-1 text-left font-normal">Takes</th><th class="pb-1 text-left font-normal">Sends</th></tr></thead>
        <tbody>${rows}</tbody></table>
      <p class="mt-1.5 border-t border-slate-900/5 pt-1.5 text-xs dark:border-white/5 ${was && !same(r.exported, was.exported) ? "shadow-[inset_2px_0_0] shadow-uoft-500 pl-1.5" : ""}">${offerLine}</p>
    </section>`;
  }
  // The tables of every router at a step, always in the order of their
  // numbers: the router in focus shaded, cells the step changed marked.
  function ribsAt(t, shown, focusOn, pinned) {
    const close = pinned ? `<button type="button" class="btn ml-auto py-0.5 text-xs" data-close data-tip="Router ${focusOn} is kept in focus">Follow the moments</button>` : "";
    return `<div class="mb-2 flex min-h-8 flex-wrap items-center gap-x-3"><p class="label">What goes in and out at step ${shown}</p>
        <span class="muted flex items-center gap-1.5 text-xs"><span class="inline-block h-3 w-0.5 bg-uoft-500"></span>changed</span>${close}</div>
      <div class="grid gap-3 md:grid-cols-2">${[...Array(n).keys()].map((i) => ribRows(t, shown, i, i === focusOn)).join("")}</div>`;
  }



  // The next router inside an AS towards each other, as the simulator finds
  // it (shortest in oracle.go): Floyd-Warshall over the links inside an AS,
  // a cost of 0 taking a link away, ties to the lower router.
  function shortest(costs) {
    const dist = [], next = [];
    for (let a = 0; a < n; a++) {
      dist.push(new Array(n).fill(Infinity)); next.push(new Array(n).fill(-1));
      dist[a][a] = 0; next[a][a] = a;
    }
    inst.links.forEach(([a, b], k) => {
      if (asIndex(a) !== asIndex(b) || costs[k] <= 0) return;
      for (const [x, y] of [[a, b], [b, a]]) if (costs[k] < dist[x][y]) { dist[x][y] = costs[k]; next[x][y] = y; }
    });
    for (let k = 0; k < n; k++) for (let a = 0; a < n; a++) for (let b = 0; b < n; b++)
      if (dist[a][k] + dist[k][b] < dist[a][b]) { dist[a][b] = dist[a][k] + dist[k][b]; next[a][b] = next[a][k]; }
    return next;
  }

  function draw(side) {
    const sec = root.querySelector(`[data-side=${side}]`);
    const t = traces[side], c = palette(), svg = sec.querySelector("[data-graph]");
    svg.replaceChildren();
    if (!t) return;
    const shown = side === "right" ? Math.min(step, t.steps.length) : besideStep();
    const s = shown ? t.steps[shown - 1] : null;
    const loop = new Set(s ? s.loop || [] : []);
    // The routers of the problem from the step it shows: a loop as it forms, routers waiting while they wait.
    const ringed = finding.kind === "transient-loop" ? loop
      : finding.kind === "transient-blocked" ? new Set(s ? s.routers.map((r, i) => (r.waits && r.best === null ? i : -1)).filter((i) => i >= 0) : [])
      : t.problem && step >= t.problem.at ? hitOf(t.mode) : new Set();
    const defs = el("defs", {});
    for (const [id, color] of [["route", c.route], ["loop", c.problem], ["message", c.message]]) {
      const m = el("marker", { id: `${side}-${id}`, viewBox: "0 0 10 10", refX: 0, refY: 5, markerWidth: 5, markerHeight: 5, orient: "auto-start-reverse" });
      m.append(el("path", { d: "M0,0 L10,5 L0,10 z", fill: color }));
      defs.append(m);
    }
    svg.append(defs);
    const down = new Set(), costs = inst.links.map((_, k) => (inst.costs && inst.costs[k] > 0 ? inst.costs[k] : 1));
    for (const st of t.steps.slice(0, shown)) if (st.kind === "event") {
      const a = st.event.from ?? 0, b = st.event.to ?? 0;
      if (["down", "up"].includes(st.event.kind)) {
        const key = [a, b].sort().join("-");
        st.event.kind === "down" ? down.add(key) : down.delete(key);
      }
      if (st.event.kind === "igp") inst.links.forEach(([x, y], k) => {
        if (((x === a && y === b) || (x === b && y === a)) && asIndex(x) === asIndex(y)) costs[k] = st.event.value ?? 0;
      });
    }
    const igp = inst.as && inst.as.length ? shortest(costs) : null;
    for (const [a, b] of inst.links) {
      const [x1, y1] = at(a), [x2, y2] = at(b);
      const peer = (inst.peers || []).some(([p, q]) => (p === a && q === b) || (p === b && q === a));
      const gone = down.has([a, b].sort().join("-"));
      svg.append(el("line", { x1, y1, x2, y2, stroke: c.link, "stroke-width": 3.5, "stroke-dasharray": peer || gone ? "7 5" : "", opacity: gone ? 0.35 : 1 }));
    }
    if (s) s.routers.forEach((r, i) => {
      if (r.next_hop < 0 || r.next_hop === i) return;
      // Inside an AS a packet takes the IGP's next router towards the BGP next hop.
      const to = igp && asIndex(r.next_hop) === asIndex(i) ? igp[i][r.next_hop] : r.next_hop;
      if (to < 0 || to === i) return;
      const inLoop = loop.has(i) && loop.has(to);
      arrow(svg, side, i, to, inLoop ? c.problem : c.route, inLoop ? "loop" : "route", false, 2.8);
    });
    if (s && s.kind !== "event") arrow(svg, side, s.from, s.to, c.message, "message", true, 3, 9);
    const labels = [];
    for (let i = 0; i < n; i++) {
      const [x, y] = at(i);
      const r = s ? s.routers[i] : null;
      const state = !r ? (i === origin ? "route" : "none") : r.waits ? "waits" : r.best !== null ? "route" : "none";
      const fill = { route: c.route, waits: c.waits, none: c.none }[state];
      const g = el("g", { "data-router": i, style: "cursor:pointer" });
      if (affected.has(t.mode) && ringed.has(i)) g.append(el("circle", { cx: x, cy: y, r: 17, fill: "none", stroke: c.problem, "stroke-width": 3 }));
      if (side === "right" && focus() === i) g.append(el("circle", { cx: x, cy: y, r: ringed.has(i) && affected.has(t.mode) ? 21.5 : 16, fill: "none", stroke: c.ring, "stroke-width": 1.5 }));
      g.append(i === origin
        ? el("rect", { x: x - 10, y: y - 10, width: 20, height: 20, fill, stroke: state === "none" ? "#94a3b8" : "none", transform: `rotate(45 ${x} ${y})` })
        : el("circle", { cx: x, cy: y, r: 11.5, fill, stroke: state === "none" ? "#94a3b8" : "none" }));
      const label = el("text", { x, y: y + 4.5, "text-anchor": "middle", "font-size": 13, "font-weight": 600, fill: state === "route" ? c.text : state === "waits" ? "#1e1b4b" : c.noneText });
      label.textContent = i;
      g.append(label);
      g.append(el("circle", { cx: x, cy: y, r: 22, fill: "transparent" }));  // a finger-sized target
      svg.append(g);
      labels.push(`router ${i} ${state === "route" ? "has a route" : state === "waits" ? "waits" : "has no route"}`);
    }
    svg.setAttribute("aria-label", labels.join(", "));
    if (side === "left") root.querySelector("[data-summary]").innerHTML = besideSummary();
  }

  // The timeline of the large run, built once per run and theme: at most
  // 400 cells, a cell of many steps showing the worst of them. The current
  // step's cell stands taller, on a long run, whose cells are thin, a line
  // marks it. A step only moves that mark.
  let cells = [], active = null, cursor = null;
  function buildTimeline() {
    const t = traces.right;
    timeline.replaceChildren();
    cells = [];
    active = cursor = null;
    if (!t) return;
    const c = palette(), total = most(), count = Math.min(total, 400), single = total <= 60;
    timeline.style.gap = single ? "2px" : "0";
    for (let k = 0; k < count; k++) {
      const from = Math.floor((k * total) / count), to = Math.max(from + 1, Math.floor(((k + 1) * total) / count));
      const cell = document.createElement("span"), part = t.steps.slice(from, to);
      cell.style.cssText = `flex:1 1 0;min-width:0;height:12px;border-radius:${single ? 3 : 0}px;transition:height .12s`;
      // The step where the problem shows is filled red, as a loop is.
      const problem = t.problem && t.problem.at > from && t.problem.at <= to;
      cell.style.background = problem || part.some((s) => s.loop && s.loop.length) ? c.problem : part.some((s) => s.routers.some((r) => r.waits)) ? c.waits
        : c.step;
      cells.push([from, to, cell]);
      timeline.append(cell);
    }
    // Before the first step, a cell of its own: step 0 is a place on the timeline too.
    const start = document.createElement("span");
    start.style.cssText = `flex:0 0 10px;height:12px;border-radius:3px;margin-right:${single ? 0 : 3}px;background:${c.none};box-shadow:inset 0 0 0 1px ${c.link};transition:height .12s`;
    start.dataset.tip = "Before the first step";
    timeline.prepend(start);
    cells.unshift([-1, 0, start]);
    if (!single) {
      cells[1][2].style.borderRadius = "3px 0 0 3px";
      cells[cells.length - 1][2].style.borderRadius = "0 3px 3px 0";
    }
    if (!single) {
      cursor = document.createElement("span");
      cursor.style.cssText = `position:absolute;top:0;bottom:0;width:3px;border-radius:2px;background:${c.ring};box-shadow:0 0 0 2px ${c.page};pointer-events:none`;
      timeline.append(cursor);
    }
    timeline.setAttribute("aria-valuemax", total);
    moveCursor();
  }
  function moveCursor() {
    const t = traces.right;
    if (!t || !cells.length) return;
    const total = most();
    // Step k is the k-th message: the cell that holds steps from + 1 to to.
    const now = cells.find(([from, to]) => step > from && step <= to)?.[2];
    // The cell of the step stands taller. On a long run, whose cells are thin, a line marks it, the start cell still stands.
    const mark = cursor && now !== cells[0][2] ? null : now;
    if (cursor) {
      cursor.hidden = !now || !!mark;
      if (now && !mark) cursor.style.left = `${now.offsetLeft + now.offsetWidth / 2 - 1.5}px`;
    }
    if (mark !== active) {
      if (active) active.style.height = "12px";
      if (mark) mark.style.height = "20px";
      active = mark;
    }
    timeline.setAttribute("aria-valuenow", step);
    timeline.setAttribute("aria-valuetext", `step ${step} of ${total}${t.problem && step === t.problem.at ? ", the problem" : ""}`);
  }

  const most = () => (traces.right ? traces.right.steps.length : 0);

  // The point of the run beside: after the same events as the large run,
  // as many messages on as the large run is since the last of them. Where
  // the large run comes to rest before its next event, or ends, the run
  // beside stands where it comes to rest itself: runs converge in their own order.
  const eventsUpTo = (t, k) => t.steps.slice(0, k).filter((x) => x.kind === "event").length;
  // The step of a run's e-th event, 1 the first, and the last step before its next one or the end.
  function phase(t, e) {
    // A run cut short before its e-th event stands at its end.
    if (e && t.steps.filter((x) => x.kind === "event").length < e) return [t.steps.length, t.steps.length];
    let seen = 0, from = 0;
    for (let k = 0; k < t.steps.length; k++) {
      if (t.steps[k].kind !== "event") continue;
      if (++seen === e) from = k + 1;
      else if (seen === e + 1) return [from, k];
    }
    return [from, t.steps.length];
  }
  function besideStep() {
    const t = traces.left, big = traces.right;
    if (!t || !big || !step) return 0;
    const e = eventsUpTo(big, step);
    const [bigFrom, bigTo] = phase(big, e), [from, to] = phase(t, e);
    if (step >= bigTo) return to;
    return Math.min(from + (step - bigFrom), to);
  }
  const cap = (x) => x.charAt(0).toUpperCase() + x.slice(1);
  const without = (st) => st.routers.map((r, i) => (r.best === null && !r.waits ? i : -1)).filter((i) => i >= 0);
  // What the run beside did on the way to this point, in one sentence.
  function besideSummary() {
    const t = traces.left, big = traces.right;
    if (!t || !big) return "";
    const b = besideStep(), e = step ? eventsUpTo(big, step) : 0;
    if (!b) return '<span class="muted">Before the first step</span>';
    let a = 0, seen = 0;
    if (e) for (let k = 0; k < t.steps.length; k++) if (t.steps[k].kind === "event" && ++seen === e) { a = k; break; }
    const part = t.steps.slice(a, b), last = t.steps[b - 1], parts = [];
    const looped = part.find((x) => x.loop && x.loop.length);
    if (looped) parts.push(`<b class="text-rose-700 dark:text-rose-300">packets circle on the way</b> (${looped.loop.join("→")})`);
    if (part.some((x) => x.routers.some((r) => r.waits))) parts.push("routers wait on the way");
    const none = without(last);
    const end = b === t.steps.length && !t.result.converged ? "still not at rest"
      : none.length ? `${routers(none)} ${none.length > 1 ? "have" : "has"} no route` : "every router has a route";
    const after = e ? ` after the same ${e > 1 ? `${e} events` : "event"}` : "", sent = e ? b - a - 1 : b;
    const when = b !== phase(t, e)[1] ? `${t.mode}${after}, ${sent} message${sent === 1 ? "" : "s"} on`
      : b === t.steps.length && !t.result.converged ? `${t.mode}${after}` : `${t.mode} at rest${after}`;
    return `<span class="muted">${when}:</span> ${[...parts, (parts.length ? "then " : "") + end].join(", ")}.`;
  }

  // The key moments of the large run, computed once per run: events, the
  // problem, loops forming and ending, routers losing a route, waiting and
  // getting one again, and the end. A moment names its router in focus.
  let moments = [];
  function keyMoments(t) {
    const out = [], steps = t.steps, end = steps.length;
    const had = new Array(n).fill(false), told = new Set();
    let everyone = false, repeats = false;
    for (let k = 1; k <= end; k++) {
      const s = steps[k - 1], prev = k > 1 ? steps[k - 2] : null, said = [];
      let focusOn = s.kind === "event" ? s.event.from ?? 0 : s.to, weight = 0;
      if (s.kind === "event") { said.push(event(s.event)); weight = 3; }
      const loopNow = s.loop && s.loop.length, loopBefore = prev && prev.loop && prev.loop.length;
      if (loopNow && !loopBefore) { said.push(`${routers(s.loop)} forward to each other, packets circle`); focusOn = s.loop[0]; weight = Math.max(weight, 3); }
      if (!loopNow && loopBefore) { said.push("the loop ends"); weight = Math.max(weight, 1); }
      const waits = [], lose = [], back = [], learn = [], move = [];
      s.routers.forEach((r, i) => {
        const was = prev ? prev.routers[i] : null;
        if (r.waits && !(was && was.waits)) waits.push(i);
        else if (was && was.best !== null && r.best === null && !r.waits) lose.push(i);
        else if (had[i] && was && (was.best === null || was.waits) && r.best !== null && !r.waits) back.push(i);
        else if (!had[i] && r.best !== null && i !== origin) learn.push(i);
        else if (was && was.best !== null && r.best !== null && !same(was.best, r.best)) move.push(i);
        if (r.best !== null) had[i] = true;
      });
      // How the routes spread: a router learns its first route, or takes another.
      for (const i of learn) { said.push(`router ${i} learns a route ${route(s.routers[i].best)}`); weight = Math.max(weight, 1); }
      for (const i of move) { said.push(`router ${i} takes the route ${route(s.routers[i].best)}`); weight = Math.max(weight, 1); }
      if (lose.length) { said.push(`${routers(lose)} lose${lose.length > 1 ? "" : "s"} ${lose.length > 1 ? "their" : "its"} route`); focusOn = lose[0]; weight = Math.max(weight, 2); }
      if (waits.length) { said.push(`${routers(waits)} wait${waits.length > 1 ? "" : "s"} for a route refresh`); focusOn = waits[0]; weight = Math.max(weight, 2); }
      if (back.length) { said.push(`${routers(back)} ${back.length > 1 ? "have" : "has"} a route again`); weight = Math.max(weight, 1); }
      if (!everyone && !out.some((m) => m.event) && s.routers.every((r) => r.best !== null)) {
        everyone = true;
        said.push("every router has a route"); weight = Math.max(weight, 2);
      }
      const problem = t.problem && t.problem.at === k;
      if (k === end) {
        const none = without(s), gone = steps.filter((x) => x.kind === "event").pop()?.event.kind === "withdraw";
        // A run that never rests ends on that alone, without the change of its last step.
        if (!t.result.converged) said.length = 0;
        said.push(!t.result.converged ? `still not at rest after ${end} steps${repeats ? ", the moments above repeat" : ""}`
          : gone && none.length === n ? "at rest no router has a route, as the prefix is gone"
          : `at rest ${none.length ? `${routers(none)} ${none.length > 1 ? "have" : "has"} no route` : "every router has a route"}`);
        if (none.length) focusOn = none[0];
        weight = 3;
      }
      if (problem) { weight = 4; const hit = [...hitOf(t.mode)]; if (hit.length && !said.length) said.push(`${routers(hit)} show the problem`); }
      // A run that never comes to rest goes round: a moment told once is enough.
      const text = cap(said.join(", "));
      if (said.length && told.has(text) && k !== end && !problem) repeats = true;
      else if (said.length) { told.add(text); out.push({ step: k, text, router: focusOn, weight, problem, event: s.kind === "event" }); }
    }
    // At most seven: the least telling go first, the order stays.
    while (out.length > 7) {
      const low = Math.min(...out.map((m) => m.weight));
      const k = out.findIndex((m) => m.weight === low && m.step !== end);
      if (k < 0) break;
      out.splice(k, 1);
    }
    return out;
  }
  const current = () => [...moments].reverse().find((m) => m.step <= step);
  function showMoments() {
    const now = current();
    root.querySelector("[data-moments]").innerHTML = moments.map((m, k) => `<li><button type="button" data-step="${m.step}"
      class="flex w-full items-start gap-2.5 rounded-md px-2 py-3 text-left sm:py-1.5 ${m === now ? "bg-slate-100 font-medium dark:bg-white/10" : "hover:bg-slate-50 dark:hover:bg-white/5"}">
      <span class="mt-0.5 grid size-5 shrink-0 place-content-center rounded-full text-xs tabular-nums ${m.problem ? "bg-rose-600 text-white dark:bg-rose-400 dark:text-slate-900" : m === now ? "bg-uoft-700 text-white dark:bg-uoft-300 dark:text-slate-900" : "bg-slate-200 dark:bg-slate-700"}">${k + 1}</span>
      <span>${m.text}${m.problem ? ' <span class="text-rose-700 dark:text-rose-300">· the problem</span>' : ""}</span></button></li>`).join("")
      || '<li class="muted">Loading the run…</li>';
    for (const b of root.querySelectorAll("[data-moments] [data-step]")) b.onclick = () => { stop(); delete chosen.right; go(Number(b.dataset.step)); };
    // The list scrolls within its height: the current moment stays in view.
    const list = root.querySelector("[data-moments]"), here = list.querySelector(".font-medium");
    if (here) {
      const top = here.offsetTop - list.offsetTop, bottom = top + here.offsetHeight;
      if (top < list.scrollTop) list.scrollTop = top;
      else if (bottom > list.scrollTop + list.clientHeight) list.scrollTop = bottom - list.clientHeight;
    }
  }

  // The router in focus: one clicked, else the one the moment names when the
  // run stands at it, else the one the step reaches.
  function focus() {
    const t = traces.right;
    if (!t || !step) return undefined;
    if (chosen.right !== undefined) return chosen.right;
    const m = current();
    if (m && m.step === step) return m.router;
    const s = t.steps[step - 1];
    return s.kind === "event" ? s.event.from ?? 0 : s.to;
  }
  function showRib() {
    const box = root.querySelector("[data-tables]"), t = traces.right, i = focus();
    if (!t || i === undefined) { box.innerHTML = '<p class="label">RIBs</p><p class="muted mt-2">Before the first step: only the origin holds its prefix.</p>'; return; }
    const pinned = chosen.right !== undefined;
    box.innerHTML = ribsAt(t, Math.min(step, t.steps.length), i, pinned);
    for (const b of box.querySelectorAll("[data-router-pick]")) b.onclick = () => { chosen.right = Number(b.dataset.routerPick); show(); };
    const close = box.querySelector("[data-close]");
    if (close) close.onclick = () => { delete chosen.right; show(); };
    for (const b of box.querySelectorAll("[data-go]")) b.onclick = () => { stop(); go(Number(b.dataset.go)); };
  }

  function show() {
    step = Math.min(step, most());
    counter.textContent = `step ${step} / ${most()}`;
    draw("right");
    draw("left");
    moveCursor();
    showMoments();
    showRib();
    drawWindows();
  }

  // A click picks the cell under the pointer, and of a cell of many steps its last.
  const pick = (e) => {
    if (!cells.length) return;
    // The cell under the pointer by its own place, the start cell being narrower than the others.
    const k = cells.findIndex(([, , cell]) => e.clientX < cell.getBoundingClientRect().right);
    stop();
    go(cells[k < 0 ? cells.length - 1 : k][1]);
  };
  timeline.addEventListener("pointerdown", (e) => { timeline.setPointerCapture(e.pointerId); pick(e); });
  timeline.addEventListener("pointermove", (e) => { if (timeline.hasPointerCapture(e.pointerId)) pick(e); });
  timeline.addEventListener("keydown", (e) => {
    const by = { ArrowRight: 1, ArrowUp: 1, ArrowLeft: -1, ArrowDown: -1 }[e.key];
    if (by) { e.preventDefault(); e.stopPropagation(); stop(); go(step + by); }
    if (e.key === "Home") { e.preventDefault(); stop(); go(0); }
    if (e.key === "End") { e.preventDefault(); stop(); go(most()); }
  });

  async function load(side) {
    const sec = root.querySelector(`[data-side=${side}]`);
    const mode = root.querySelector(`[data-mode=${side}]`).value;
    sec.querySelector("[data-state]").textContent = "";
    sec.querySelector("[data-wait]").hidden = false;
    delete traces[side];
    if (side === "right") moments = [];
    show();
    const res = await fetch(`/simulation/${root.dataset.search}/${root.dataset.finding}/trace?mode=${encodeURIComponent(mode)}`);
    if (root.querySelector(`[data-mode=${side}]`).value !== mode) return;  // another mode was chosen meanwhile
    sec.querySelector("[data-wait]").hidden = true;
    if (!res.ok) { sec.querySelector("[data-state]").textContent = (await res.json().catch(() => ({}))).detail || "The simulator failed."; return; }
    const t = await res.json();
    if (affected.has(t.mode)) t.problem = analyse(t);
    traces[side] = t;
    const messages = t.steps.filter((x) => x.kind !== "event").length;
    sec.querySelector("[data-state]").textContent = `${messages} messages · ${t.result.converged ? "comes to rest" : "never at rest"}`;
    if (side === "right") {
      moments = keyMoments(t);
      // One sentence under the title: why it happens, else what happens.
      if (t.problem) document.querySelector("[data-problem]").textContent = why(t) || t.problem.text;
      step = moments.length ? moments[0].step : 0;
      buildTimeline();
    }
    show();
  }

  const play = root.querySelector("[data-act=play]");
  const speed = () => Number(root.querySelector("input[name=speed]:checked")?.value || 1);
  const playing = (on) => { play.innerHTML = `${UI.icon(on ? "pause" : "play")}<span>${on ? "Pause" : "Play"}</span>`; };
  const stop = () => { clearInterval(timer); timer = null; playing(false); };
  const loop = root.querySelector("[data-act=loop]");
  const looping = () => loop.getAttribute("aria-pressed") === "true";
  // At the end a loop starts over, else playing stops.
  const tick = () => { clearInterval(timer); timer = setInterval(() => (step < most() ? go(step + 1) : looping() ? go(1) : stop()), 1000 / speed()); };
  const go = (to) => { step = Math.max(0, Math.min(most(), to)); show(); };
  const moment = (by) => {
    const k = moments.indexOf(current());
    const to = by > 0 ? moments[k + 1] : step > (current()?.step ?? 0) ? current() : moments[k - 1];
    if (to) { stop(); delete chosen.right; go(to.step); }
  };
  for (const r of root.querySelectorAll("input[name=speed]")) r.addEventListener("change", () => { if (timer) tick(); });
  root.querySelector("[data-act=first]").onclick = () => { stop(); go(0); };
  loop.onclick = () => loop.setAttribute("aria-pressed", !looping());
  root.querySelector("[data-act=prev]").onclick = () => { stop(); go(step - 1); };
  root.querySelector("[data-act=next]").onclick = () => { stop(); go(step + 1); };
  play.onclick = () => {
    if (timer) return stop();
    if (step >= most()) step = 0;
    playing(true);
    tick();
  };
  document.addEventListener("keydown", (e) => {
    if (e.target.closest("input, select, textarea, button, summary, [role=slider]")) return;
    if (e.key === "ArrowRight") moment(1);
    if (e.key === "ArrowLeft") moment(-1);
  });
  // A menu whose mode has the problem is red, as are such modes in its list (ui.js carries both over).
  const mark = (select) => {
    const bad = select.selectedOptions[0]?.hasAttribute("data-problem");
    select.classList.toggle("text-rose-700", bad), select.classList.toggle("dark:text-rose-300", bad), select.classList.toggle("border-rose-400", bad);
  };
  for (const side of ["left", "right"]) {
    const select = root.querySelector(`[data-mode=${side}]`);
    mark(select);
    select.onchange = () => { mark(select); load(side); };
  }
  // On a desktop a click on a router opens its table as a window of its own,
  // to drag by its title and close, several at once, following the steps.
  // On a touch screen it keeps the router in focus.
  const windows = new Map();
  const desktop = matchMedia("(pointer: fine) and (min-width: 768px)").matches;
  function drawWindows() {
    const t = traces.right;
    for (const [i, w] of windows) {
      const body = w.querySelector("[data-body]");
      body.innerHTML = t && step ? ribRows(t, Math.min(step, t.steps.length), i, false, true) : '<p class="muted text-xs">Before the first step.</p>';
      // The window has the title and the frame: the block's own go.
      const block = body.querySelector("section");
      if (block) { block.className = ""; block.firstElementChild.remove(); }
    }
  }
  function openWindow(i) {
    if (windows.has(i)) return windows.get(i).focus();
    const w = document.createElement("div");
    w.tabIndex = -1;
    // On the page, not the screen: it stays where it was put while the page scrolls.
    w.className = "card absolute z-40 w-[26rem] max-w-[90vw] p-0 shadow-lg";
    w.style.left = `${scrollX + 120 + 30 * windows.size}px`;
    w.style.top = `${scrollY + 120 + 30 * windows.size}px`;
    w.innerHTML = `<div data-drag class="flex cursor-move items-center gap-2 border-b border-slate-900/10 px-3 py-1.5 text-sm select-none dark:border-white/10">
      <b class="mr-auto">Router ${i}</b><button type="button" class="btn btn-icon size-7 border-transparent shadow-none" aria-label="Close">✕</button></div>
      <div data-body class="p-2 text-sm"></div>`;
    w.querySelector("button").onclick = () => { windows.delete(i); w.remove(); };
    const bar = w.querySelector("[data-drag]");
    bar.addEventListener("pointerdown", (e) => {
      if (e.target.closest("button")) return;
      const dx = e.pageX - w.offsetLeft, dy = e.pageY - w.offsetTop;
      bar.setPointerCapture(e.pointerId);
      const move = (m) => { w.style.left = `${Math.max(0, m.pageX - dx)}px`; w.style.top = `${Math.max(0, m.pageY - dy)}px`; };
      bar.addEventListener("pointermove", move);
      bar.addEventListener("pointerup", () => bar.removeEventListener("pointermove", move), { once: true });
    });
    document.body.append(w);
    windows.set(i, w);
    drawWindows();
  }
  root.querySelector("[data-side=right] [data-graph]").addEventListener("click", (e) => {
    const g = e.target.closest("[data-router]");
    if (!g) return;
    const i = Number(g.dataset.router);
    if (desktop) return openWindow(i);
    chosen.right === i ? delete chosen.right : (chosen.right = i);
    show();
  });
  load("right");
  load("left");
  document.addEventListener("lab:theme", () => { buildTimeline(); show(); });
  new ResizeObserver(() => moveCursor()).observe(timeline);  // the line stands at a cell's middle, in pixels

  // The network and its policies, one kind of fact a row.
  const facts = [["Routers", `${n}, numbered 0 to ${n - 1}`], ["Origin", `router ${origin}`]];
  if (inst.as && inst.as.length) for (const [asn, rs] of Object.entries(members)) if (rs.length > 1) facts.push(["iBGP", `${routers(rs)} form AS ${asn}`]);
  const rel = [
    ...(inst.customers || []).map(([p, cst]) => `${cst} is a customer of ${p}`),
    ...(inst.peers || []).map(([a, b]) => `${a} and ${b} are peers`),
    ...(inst.siblings || []).map(([a, b]) => `${a} and ${b} are siblings`),
  ];
  if (rel.length) facts.push(["Relations", rel.join(", ")]);
  if ((inst.leakers || []).length) facts.push(["Leaks", `${routers(inst.leakers)} pass every route to every neighbor`]);
  if ((inst.route_servers || []).length) facts.push(["Route servers", routers(inst.route_servers)]);
  if (poison.length) facts.push(["Poison", `the origin names AS ${poison.join(", ")}`]);
  for (const s of inst.sessions || []) {
    const a = s.from ?? 0, b = s.to ?? 0;
    if (s.local_pref) facts.push(["Preference", `router ${b} gives routes from router ${a} local preference ${esc(s.local_pref)}`]);
    if (s.deny_export) facts.push(["Filter", `router ${a} sends router ${b} nothing`]);
    if (s.deny_via) facts.push(["Filter", `router ${a} sends router ${b} no path through AS ${esc(s.deny_via)}`]);
    if (s.deny_import) facts.push(["Filter", `router ${b} rejects everything from router ${a}`]);
    if (s.prepend) facts.push(["Prepend", `router ${a} adds its AS ${esc(s.prepend)} times towards router ${b}`]);
    if (s.med) facts.push(["MED", `router ${a} sets ${esc(s.med)} towards router ${b}`]);
    if (s.tag) facts.push(["Tag", `router ${b} tags routes from router ${a} with ${esc(s.tag)}`]);
    if (s.partial_transit) facts.push(["Transit", `router ${a} sends its customer router ${b} only its customers' routes`]);
  }
  // An event the simulator holds back until the network is quiet carries a huge after.
  for (const e of inst.events || []) if (e.kind !== "expect") facts.push(["Event", `${e.after >= 2 ** 29 ? "once the network is quiet" : `after ${e.after} messages`}, ${event(e)}`]);
  document.querySelector("[data-policies]").innerHTML = facts.map(([k, v], i) =>
    `<dt class="muted">${i && facts[i - 1][0] === k ? "" : k}</dt><dd>${v}</dd>`).join("");
})();
