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
  // A step is two phases: its message on the way, then the state after it. The page alternates between them.
  let step = 0, timer = null, phase = "state";
  const inMessage = () => phase === "message" && step > 0;
  const NS = "http://www.w3.org/2000/svg";
  const el = (name, attrs) => { const e = document.createElementNS(NS, name); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); return e; };
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const dark = () => document.documentElement.dataset.theme === "dark";  // as base.html sets it
  const palette = () => dark()
    ? { route: "#93b0e0", text: "#0f172a", none: "#1e293b", noneText: "#cbd5e1", waits: "#a78bfa", problem: "#fb7185", message: "#94a3b8", link: "#334155", step: "#1e293b", ring: "#93b0e0", page: "#0f172a", as: ["rgba(147,176,224,.16)", "rgba(148,163,184,.18)", "rgba(148,163,184,.10)"] }
    : { route: "#1e3765", text: "#ffffff", none: "#e2e8f0", noneText: "#1e293b", waits: "#a78bfa", problem: "#e11d48", message: "#64748b", link: "#cbd5e1", step: "#e2e8f0", ring: "#1e3765", page: "#ffffff", as: ["rgba(30,55,101,.09)", "rgba(100,116,139,.12)", "rgba(71,85,105,.08)"] };

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
    // A route never breaks across lines: a no-break space after "via", word joiners around the arrows.
    return "via\u00a0" + passed.map(hop).join("\u2060→\u2060") + (poisoned ? `, poisons AS ${poison.join(", ")}` : "");
  };
  const PURE_OBGP = ["obgp-rp", "obgp-sp", "obgp-hp", "obgp-np", "obgp-paper"];  // one table, every router OBGP
  const routers = (list) => (list.length === 1 ? `router ${list[0]}` : `routers ${list.slice(0, -1).join(", ")} and ${list[list.length - 1]}`);
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const has = (list, p) => list.some((q) => same(q, p));
  const plain = (mode) => mode === "bgp" || mode === "bgp-pn";  // BGP's decision, with one table or one per neighbor

  // Roles of the routers: route reflectors and their clients, route servers,
  // the ASes of several routers and the confederations.
  const reflectors = new Set((inst.ibgp || []).flatMap((x) => x.reflectors || []));
  const servers = new Set(inst.route_servers || []);
  const several = Object.entries(members).filter(([, rs]) => rs.length > 1);
  const confedOf = (r) => (inst.confeds || []).find((c) => c.members.includes(asIndex(r)));
  function role(r) {
    if (servers.has(r)) return "route server";
    if (reflectors.has(r)) return "route reflector";
    const asn = asNumber(asIndex(r)), rr = (inst.ibgp || []).find((x) => asNumber(x.as) === asn);
    if (rr && (members[asn] || []).length > 1) return `client of ${routers(rr.reflectors)}`;
    return "";
  }
  // Why router i sends its packets where it does, in a few words: "2 prefers 4's route but reaches 4 only through 1".
  function reason(r, i) {
    const best = (r.in || []).find((x) => x.fate === "best"), others = (r.in || []).filter((x) => x.fate === "admitted");
    const whose = best ? `${best.from}'s route` : "its route";
    const knows = !best ? `router ${i} holds ${route(r.best)}` : others.length ? `router ${i} prefers ${whose}` : `router ${i} only knows ${whose}`;
    const to = forwardOf(r, i);
    return to !== r.next_hop && r.next_hop >= 0 ? `${knows} but reaches ${r.next_hop} only through ${to}` : knows;
  }

  // The router whose packets the graph follows, null for every router's first hop.
  const followSelect = root.querySelector("[data-follow]");
  const followFrom = () => (followSelect && followSelect.value !== "" ? Number(followSelect.value) : null);
  followSelect?.addEventListener("change", () => show());
  const forwardOf = (r, i) => (r.forward !== undefined ? r.forward : r.next_hop);

  // Why a case lies outside the model of the proofs, by its family.
  const outside = {
    communities: "communities stop routes on the way", tagging: "routers tag routes and filter on the tags", poison: "the origin poisons ASes",
    "export-filter": "export filters", "as-path-filter": "filters on the AS path", prepend: "prepending", "import-filter": "import filters",
    "local-pref": "local preferences set by policy", "ibgp-mesh": "an AS of several routers with iBGP", "ibgp-rr": "an AS of several routers behind a route reflector",
    "med-rr": "MED behind a route reflector", confed: "a confederation", "route-server": "a route server", "route-leak": "a route leak",
  }[inst.family];

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
    const bgp = example.results && example.results.bgp;
    switch (finding.kind) {
      case "transient-loop": {
        const r = span((s) => s.loop && s.loop.length);
        if (r) return { at: r[0], text: `On the way to rest, ${routers(steps[r[0] - 1].loop)} send packets to each other for a moment.` };
        break;
      }
      case "transient-blocked": {
        const r = span((s, k) => s.routers.some((x, i) => x.waits && lost[k ?? steps.indexOf(s)][i]));
        if (r) {
          const who = steps[r[0] - 1].routers.map((x, i) => (x.waits ? i : -1)).filter((i) => i >= 0);
          return { at: r[0], text: `On the way to rest, ${routers(who)} wait${who.length > 1 ? "" : "s"} for a route refresh without a route and drop${who.length > 1 ? "" : "s"} packets for a moment.` };
        }
        break;
      }
      case "transient-hole": {
        const k = lost.findIndex((row) => row.some((g, i) => g && last.routers[i].best !== null));
        if (k >= 0) {
          const who = lost[k].map((g, i) => (g && last.routers[i].best !== null ? i : -1)).filter((i) => i >= 0);
          return { at: k + 1, text: `On the way to rest, ${routers(who)} lose${who.length > 1 ? "" : "s"} the route for a moment and drop${who.length > 1 ? "" : "s"} packets meanwhile.` };
        }
        break;
      }
      case "loop":
        return { at: end, text: `${cap(routers(last.loop || [...hit]))} send packets to each other, forever.` };
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
      return near.slice(0, 1).map((x) => {
        // From the run itself: what router x sends router h, or why not, and what h makes of it.
        const sent = (s.routers[x].out || []).find((o) => o.to === h), got = (s.routers[h].in || []).find((o) => o.from === x);
        const theirs = bgp && bgp.exported && bgp.exported[x] && !same(bgp.exported[x], s.routers[x].exported) ? ` BGP would offer ${route(bgp.exported[x])}.` : "";
        // What the router offers and what stops it, in one breath: "Router 1 offers only via 2→0, and its export filter drops that."
        if (sent && !sent.path && sent.not === "nothing to offer") return `Router ${x} has nothing to offer router ${h}.${theirs}`;
        if (sent && !sent.path) {
          // The rule behind it, concrete where the network says it.
          const x0 = (inst.sessions || []).find((y) => (y.from ?? 0) === x && (y.to ?? 0) === h) || {};
          const concrete = sent.not === "the export filter drops it" && x0.deny_via ? `but it sends router ${h} no path through AS ${esc(x0.deny_via)}`
            : sent.not === "the relation forbids it" && relationOf(x, h) ? `but router ${h} is its ${relationOf(x, h)} and gets only customer routes` : "";
          const stop = concrete || { "the export filter drops it": "and its export filter drops that", "the relation forbids it": `which it may not pass to router ${h}`,
            "a community withholds it": `which a community keeps from router ${h}`, "its AS is in the path": `which runs through router ${h}'s AS`,
            "back to its source": `which came from router ${h}`, "the session is down": `but its session with router ${h} is down` }[sent.not] || `but ${esc(sent.not)}`;
          return `Router ${x} offers only ${route(s.routers[x].exported)}, ${stop}.${theirs}`;
        }
        const fate = got && got.fate !== "none" ? got.fate : "";
        const told = { "set aside": "sets it aside", filtered: "filters it on import", loop: "rejects it as a loop", pruned: "has pruned it", dropped: "does not keep it" }[fate];
        return `Router ${x} sends router ${h} ${route(sent ? sent.path : s.routers[x].exported)}, which router ${h} ${told || "does not admit"}.${theirs}`;
      }).join(" ");
    }).join(" ");
    switch (finding.kind) {
      case "unreachable": case "transient-hole": case "black-hole":
        return lacking([...hitOf(t.mode)].filter((h) => s.routers[h].best === null).slice(0, 1));
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
        // Short, one clause per router of the loop: what it knows or prefers, and the detour to its next hop.
        const chain = [];
        for (let i = loop[0], k = 0; k < loop.length && !chain.some((x) => x.i === i); k++) {
          chain.push({ i, r: s.routers[i] });
          i = forwardOf(s.routers[i], i);
        }
        return chain.map(({ i, r }) => cap(reason(r, i))).join(". ") + ".";
      }
      case "leaked": {
        // The network says who leaks: a router that passes routes between its providers or peers by policy.
        const leakers = inst.leakers || [];
        return leakers.length ? `${cap(routers(leakers))} pass${leakers.length > 1 ? "" : "es"} routes from a provider or peer on to another provider or peer, a leak by policy.` : "";
      }
      case "inconsistent-export": {
        // Routers of one AS that send different paths, as the routers send them: their first path out, own AS dropped.
        const sent = (i) => ((s.routers[i].out || []).find((o) => o.path && asIndex(o.to) !== asIndex(i)) || {}).path;  // to another AS, so with its own AS first
        const who = [...hitOf(t.mode)].filter((i) => sent(i));
        const paths = who.map((i) => sent(i).slice(1));
        if (who.length < 2 || paths.every((p) => same(p, paths[0]))) return "";
        const why = PURE_OBGP.includes(t.mode) ? ": each offers the worst path it admitted" : "";
        return `${cap(who.map((i, k) => `router ${i} sends ${route(paths[k])}`).join(", "))}, though one AS${why}.`;
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
    const line = el("line", { x1: x1 + (dx / d) * k + ox, y1: y1 + (dy / d) * k + oy, x2: x2 - (dx / d) * (k + head) + ox, y2: y2 - (dy / d) * (k + head) + oy,
      stroke: color, "stroke-width": width, "stroke-dasharray": dashed ? "5 3.5" : "", "marker-end": `url(#${side}-${marker})` });
    svg.append(line);
    return line;
  }

  // The windows of routers and links, short: what a router uses, where its packets go, what it hears and
  // what it sends, routes as the rest of the page names them, "via 3→0".
  const FATE = { best: "uses it", admitted: "keeps it", "set aside": "sets it aside", filtered: "filters it", loop: "rejects it, a loop",
    pruned: "has pruned it", dropped: "drops it" };
  const fateClass = { best: "font-medium text-uoft-700 dark:text-uoft-300", "set aside": "text-violet-700 dark:text-violet-300",
    filtered: "text-rose-700 dark:text-rose-300", loop: "text-rose-700 dark:text-rose-300", pruned: "text-rose-700 dark:text-rose-300" };
  const fate = (f) => `<span class="${fateClass[f] || "muted"}">${FATE[f] || f}</span>`;
  // A path as a neighbor gets it starts with the sender's own AS, once or prepended: the route behind it.
  const own = (i) => [asNumber(asIndex(i)), ...((confedOf(i) && [confedOf(i).id]) || [])];
  const behind = (i, p) => { let k = 0; while (k < p.length && own(i).includes(p[k])) k++; return p.slice(k); };
  const block = (title, items) => (items.length ? `<p class="label mt-3 mb-1">${title}</p><ul class="space-y-0.5">${items.map((x) => `<li>${x}</li>`).join("")}</ul>` : "");

  // A message as one line: when, which way, what, and what the receiver did with it.
  function messageLine(t, k, viewer) {
    const st = t.steps[k - 1];
    const what = st.kind === "withdraw" ? "withdraws" : st.kind === "refresh" ? "asks for a refresh" : esc(route(behind(st.from, st.path || [])));
    const got = st.kind === "update" ? (st.routers[st.to].in || []).find((o) => o.from === st.from && o.fate !== "none") : null;
    const way = viewer === undefined ? `${st.from} → ${st.to}` : st.to === viewer ? `from ${st.from}` : `to ${st.to}`;
    return `<span class="muted tabular-nums">${k}</span> ${way}: ${what}${got ? `, ${fate(got.fate)}` : ""}`;
  }
  // A link's state: what each side offers the other now, and what the other does with it.
  function linkState(t, shown, a, b) {
    const s = t.steps[shown - 1];
    const way = (x, y) => {
      const sent = (s.routers[x].out || []).find((o) => o.to === y), got = (s.routers[y].in || []).find((o) => o.from === x && o.fate !== "none");
      if (!sent) return `<span class="muted">${x} → ${y}: no session</span>`;
      if (!sent.path) return `<span class="muted">${x} → ${y}: nothing, ${notWhy(x, y, sent.not || "")}</span>`;
      return `${x} → ${y}: ${esc(route(behind(x, sent.path)))}${got ? `, ${fate(got.fate)}` : ""}`;
    };
    return `<ul class="space-y-1"><li>${way(a, b)}</li><li>${way(b, a)}</li></ul>`;
  }

  // The rules of router i, from the network: its relations and what it filters, prefers and prepends.
  const relationOf = (i, j) => {
    if ((inst.customers || []).some(([p, c]) => p === i && c === j)) return "customer";
    if ((inst.customers || []).some(([p, c]) => p === j && c === i)) return "provider";
    if ((inst.peers || []).some(([a, b]) => (a === i && b === j) || (a === j && b === i))) return "peer";
    if ((inst.siblings || []).some(([a, b]) => (a === i && b === j) || (a === j && b === i))) return "sibling";
    return "";
  };
  function rules(i) {
    const out = [], rel = { customer: [], provider: [], peer: [], sibling: [] };
    for (let j = 0; j < n; j++) if (relationOf(i, j)) rel[relationOf(i, j)].push(j);
    const named = Object.entries(rel).filter(([, js]) => js.length).map(([k, js]) => `${k}${js.length > 1 ? "s" : ""} ${js.join(" and ")}`);
    if (named.length) out.push(`${cap(named.join(", "))}.${rel.peer.length || rel.provider.length ? " Peers and providers get only its customers' routes." : ""}`);
    if ((inst.leakers || []).includes(i)) out.push("Leaks: passes every route to every neighbor.");
    for (const x of inst.sessions || []) {
      const a = x.from ?? 0, b = x.to ?? 0;
      if (a === i && x.deny_export) out.push(`Sends ${b} nothing.`);
      if (a === i && x.deny_via) out.push(`Sends ${b} no path through AS ${esc(x.deny_via)}.`);
      if (a === i && x.partial_transit) out.push(`Sends its customer ${b} only its customers' routes.`);
      if (a === i && x.prepend) out.push(`Prepends its AS ${esc(x.prepend)} times towards ${b}.`);
      if (b === i && x.deny_import) out.push(`Takes nothing from ${a}.`);
      if (b === i && x.local_pref) out.push(`Prefers routes from ${a} (local preference ${esc(x.local_pref)}).`);
    }
    return out;
  }
  // Why router i sends j nothing, said by the rule behind it.
  function notWhy(i, j, not) {
    const x = (inst.sessions || []).find((y) => (y.from ?? 0) === i && (y.to ?? 0) === j) || {};
    if (not === "the export filter drops it" && x.deny_via) return `no path through AS ${esc(x.deny_via)}`;
    if (not === "the export filter drops it" && x.deny_export) return "it sends it nothing";
    if (not === "the relation forbids it" && relationOf(i, j)) return `a ${relationOf(i, j)} gets only customer routes`;
    return esc(not);
  }

  function ribRows(t, shown, i) {
    const r = t.steps[shown - 1].routers[i];
    if (!r.in || !r.out) return '<p class="muted text-xs">Not recorded in this replay.</p>';
    const best = r.in.find((x) => x.fate === "best");
    const uses = r.best === null ? (r.waits ? "No route, waits for a refresh" : "No route")
      : !r.best.length ? "Has the prefix itself"
      : `Uses ${esc(route(r.best))}${best ? `, from ${best.from}${best.over === "ibgp" ? " over iBGP" : ""}` : ""}`;
    const to = forwardOf(r, i);
    const goes = r.next_hop < 0 || r.next_hop === i ? "" : to !== r.next_hop ? `Packets go to ${to}, on the way to ${r.next_hop}` : `Packets go to ${to}`;
    // NS-BGP sends a packet from a neighbor on the route it sends that neighbor.
    const ingress = r.ingress ? Object.entries(r.ingress).map(([q, h]) => `Packets from ${esc(q)} go to ${h.next_hop}`) : [];
    // What it hears beside the route it uses, which the first line names.
    const hears = r.in.filter((x) => x.fate !== "none" && x.fate !== "best").map((x) => `From ${x.from}: ${esc(route(x.path))}, ${fate(x.fate)}`);
    // Sends, grouped by route; "nothing to offer" says nothing.
    const groups = new Map(), not = [];
    for (const o of r.out) {
      if (o.path) { const k = esc(route(behind(i, o.path))); groups.set(k, [...(groups.get(k) || []), o.to]); }
      else if (o.not && o.not !== "nothing to offer") not.push(`<span class="muted">Not to ${o.to}: ${notWhy(i, o.to, o.not)}</span>`);
    }
    const sends = [...[...groups].map(([k, tos]) => `To ${tos.join(" and ")}: ${k}`), ...not];
    return `<p class="font-medium">${uses}</p>${goes ? `<p class="muted">${goes}</p>` : ""}${ingress.map((x) => `<p class="muted">${x}</p>`).join("")}
      ${block("Rules", rules(i))}${block("Also holds", hears)}${block("Offers", sends)}`;
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
    // In the message phase the state before the message, and the message on its way; then the state after it.
    const msg = inMessage() && step <= t.steps.length ? t.steps[step - 1] : null;
    const shown = Math.min(msg ? step - 1 : step, t.steps.length);
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
    // An AS of several routers, or a confederation, as a tint behind its routers.
    // A confederation is tinted as one, as the lab frames it.
    const tinted = [...several.map(([, rs]) => rs), ...(inst.confeds || []).map((cf) => [...Array(n).keys()].filter((r) => cf.members.includes(asIndex(r))))];
    tinted.forEach((rs, k) => rs.forEach((r) => { const [x, y] = at(r); svg.append(el("circle", { cx: x, cy: y, r: 21, fill: c.as[k % c.as.length] })); }));
    const plainCosts = inst.links.every((_, k) => !inst.costs || (inst.costs[k] || 1) === 1);
    inst.links.forEach(([a, b], k) => {
      const [x1, y1] = at(a), [x2, y2] = at(b);
      const peer = (inst.peers || []).some(([p, q]) => (p === a && q === b) || (p === b && q === a));
      const gone = down.has([a, b].sort().join("-"));
      // Inside an AS a link is the IGP's, thin and with its cost, between ASes it carries an eBGP session.
      const inside = asIndex(a) === asIndex(b);
      svg.append(el("line", { x1, y1, x2, y2, stroke: c.link, "stroke-width": inside ? 1.6 : 3.5, "stroke-dasharray": gone ? "7 5" : "", opacity: gone ? 0.35 : 1 }));
      // Peers have a dot at both ends, as in the lab's graphs.
      if (peer) for (const [fx, fy, tx, ty] of [[x1, y1, x2, y2], [x2, y2, x1, y1]]) {
        const d = Math.hypot(tx - fx, ty - fy) || 1;
        svg.append(el("circle", { cx: fx + ((tx - fx) / d) * 22, cy: fy + ((ty - fy) / d) * 22, r: 3.2, fill: c.link }));
      }
      if (inside && !plainCosts && side === "right") {  // the large graph only: the small one would make it too small to read
        // Beside the link, off the arrows that run along it.
        const d = Math.hypot(x2 - x1, y2 - y1) || 1, nx = -(y2 - y1) / d, ny = (x2 - x1) / d;
        const label = el("text", { x: (x1 + x2) / 2 + nx * 13, y: (y1 + y2) / 2 + ny * 13 + 3.5, "text-anchor": "middle", "font-size": 10.5, fill: c.message });
        label.textContent = costs[k];
        svg.append(label);
      }
    });
    // iBGP sessions are not drawn: the line above the graphs says how an AS runs iBGP, and lines would compete with the routes.
    // One router's packets followed all the way, as the simulator's walk follows them: under NS-BGP a router
    // sends a packet from a neighbor on the route it offers that neighbor, inside an AS through a tunnel to the exit.
    const follow = followFrom();
    if (s && follow !== null) {
      const seen = new Set(), walk = [];
      let at = follow, came = null, circles = false;
      for (let k = 0; k < 4 * n; k++) {
        const r = s.routers[at];
        const h = came !== null && r.ingress ? r.ingress[came] : null;
        if (came !== null && r.ingress && !h) break;
        const hop = h ? h.next_hop : r.next_hop, path = h ? h.path : r.best;
        if (hop < 0 || hop === at || path === null) break;
        const key = `${at} ${came}`;
        if (seen.has(key)) { circles = true; break; }
        seen.add(key);
        // Where the packet goes, and as whose packet the next router sees it: from the router before it, or
        // through a tunnel from the exit of this AS. Without NS-BGP every router decides alone.
        let to, from = at;
        const inside = asIndex(hop) === asIndex(at);
        if (!h) to = forwardOf(r, at);
        else if (inside) to = !path.length ? hop : neighbors(hop).find((x) => asIndex(x) !== asIndex(hop) && (asNumber(asIndex(x)) === path[0] || confedOf(x)?.id === path[0])) ?? -1;
        else to = hop;
        if (inside && path.length) from = hop;
        if (to < 0) break;
        walk.push([at, to]);
        came = r.ingress && !(inside && !path.length) ? from : null;
        at = to;
      }
      for (const [a, b] of walk) arrow(svg, side, a, b, circles ? c.problem : c.route, circles ? "loop" : "route", false, 3);
    }
    if (s && follow === null) s.routers.forEach((r, i) => {
      if (r.next_hop < 0 || r.next_hop === i) return;
      // Inside an AS a packet takes the IGP's next router towards the BGP next hop, as the simulator follows it.
      const to = r.forward !== undefined ? r.forward : igp && asIndex(r.next_hop) === asIndex(i) ? igp[i][r.next_hop] : r.next_hop;
      if (to < 0 || to === i) return;
      const inLoop = loop.has(i) && loop.has(to);
      // Both ways of a loop on one link side by side.
      // While packets circle only the loop is strong, the other routes pale: the eye goes to the problem.
      const line = arrow(svg, side, i, to, inLoop ? c.problem : c.route, inLoop ? "loop" : "route", false, inLoop || !loop.size ? 2.8 : 2, inLoop ? 4 : 0);
      if (loop.size && !inLoop) line.setAttribute("opacity", 0.3);
      // In a loop the graph says why: where the router wants its packets to go, its BGP next hop, thin and dashed.
      if (inLoop && side === "right" && to !== r.next_hop) {
        arrow(svg, side, i, r.next_hop, c.problem, "loop", true, 1.4, 6);
        const [x1, y1] = at(i), [x2, y2] = at(r.next_hop), d = Math.hypot(x2 - x1, y2 - y1) || 1;
        // Beside the router, along the way it wants.
        const note = el("text", { x: x1 + ((x2 - x1) / d) * 40 + ((y2 - y1) / d) * -12, y: y1 + ((y2 - y1) / d) * 40 + ((x2 - x1) / d) * 12, "text-anchor": "middle",
          "font-size": 11, "font-weight": 600, fill: c.problem, "paint-order": "stroke", stroke: c.page, "stroke-width": 3.5 });
        note.textContent = `wants ${r.next_hop}`;
        svg.append(note);
      }
    });
    // The message of the step, only in its phase: an arrow with what it carries.
    if (msg && msg.kind !== "event") {
      arrow(svg, side, msg.from, msg.to, c.message, "message", true, 3, 9);
      const [x1, y1] = at(msg.from), [x2, y2] = at(msg.to);
      const note = el("text", { x: (x1 + x2) / 2, y: (y1 + y2) / 2 - 10, "text-anchor": "middle", "font-size": 11, "font-weight": 600, fill: c.message,
        "paint-order": "stroke", stroke: c.page, "stroke-width": 3.5 });
      note.textContent = msg.kind === "withdraw" ? "withdraw" : msg.kind === "refresh" ? "refresh?" : route(behind(msg.from, msg.path || []));
      svg.append(note);
    }
    // Every link takes a click, the arrows along it included: it opens what flows on it.
    if (side === "right") for (const [a, b] of inst.links) {
      const [x1, y1] = at(a), [x2, y2] = at(b);
      svg.append(el("line", { x1, y1, x2, y2, stroke: "transparent", "stroke-width": 14, "data-link": `${Math.min(a, b)}-${Math.max(a, b)}`, style: "cursor:pointer" }));
    }
    const labels = [];
    for (let i = 0; i < n; i++) {
      const [x, y] = at(i);
      const r = s ? s.routers[i] : null;
      const state = !r ? (i === origin ? "route" : "none") : r.waits ? "waits" : r.best !== null ? "route" : "none";
      const fill = { route: c.route, waits: c.waits, none: c.none }[state];
      const g = el("g", { "data-router": i, style: "cursor:pointer" });
      if (affected.has(t.mode) && ringed.has(i)) g.append(el("circle", { cx: x, cy: y, r: 17, fill: "none", stroke: c.problem, "stroke-width": 3 }));
      // The router the step acts on, the one a message reaches, keeps a thin ring: nothing marks open tables.
      const act = msg || (shown === step ? s : null);
      const active = act ? (act.kind === "event" ? act.event.from ?? 0 : act.to) : -1;
      if (side === "right" && active === i) g.append(el("circle", { cx: x, cy: y, r: ringed.has(i) && affected.has(t.mode) ? 21.5 : 16, fill: "none", stroke: c.ring, "stroke-width": 1.5 }));
      g.append(i === origin
        ? el("rect", { x: x - 10, y: y - 10, width: 20, height: 20, fill, stroke: state === "none" ? "#94a3b8" : "none", transform: `rotate(45 ${x} ${y})` })
        : el("circle", { cx: x, cy: y, r: 11.5, fill, stroke: state === "none" ? "#94a3b8" : "none" }));
      const label = el("text", { x, y: y + 4.5, "text-anchor": "middle", "font-size": 13, "font-weight": 600, fill: state === "route" ? c.text : state === "waits" ? "#1e1b4b" : c.noneText });
      label.textContent = i;
      g.append(label);
      // Route reflectors and route servers carry a badge.
      const badge = servers.has(i) ? "RS" : reflectors.has(i) ? "RR" : "";
      if (badge && side === "right") {
        const b = el("text", { x: x + 13, y: y - 12, "font-size": 10.5, "font-weight": 700, fill: UI.css("--graph-role") });
        b.textContent = badge;
        g.append(b);
      }
      g.append(el("circle", { cx: x, cy: y, r: 22, fill: "transparent" }));  // a finger-sized target
      svg.append(g);
      labels.push(`router ${i} ${state === "route" ? "has a route" : state === "waits" ? "waits" : "has no route"}`);
    }
    svg.setAttribute("aria-label", labels.join(", "));
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
    let prevLoop = false;
    for (let k = 0; k < count; k++) {
      const from = Math.floor((k * total) / count), to = Math.max(from + 1, Math.floor(((k + 1) * total) / count));
      const cell = document.createElement("span"), part = t.steps.slice(from, to);
      // The step where the problem shows is filled red, as a loop is: the colour of its state.
      const problem = t.problem && t.problem.at > from && t.problem.at <= to;
      // A cell of many steps is as red as the share of its steps with a loop: a run that loops now and then stays readable.
      const share = part.filter((s) => s.loop && s.loop.length).length / part.length;
      const color = problem || share ? c.problem : part.some((s) => s.routers.some((r) => r.waits)) ? c.waits : c.step;
      const strength = problem || single ? 1 : share ? 0.2 + 0.8 * share : 1;
      if (single) {
        // A step as its two phases: the message, light, then the state in its colour. The phase shown stands taller.
        cell.style.cssText = "flex:1 1 0;min-width:0;display:flex;align-items:center;gap:1px;height:20px";
        const half = (bg, edge) => {
          const h = document.createElement("span");
          h.style.cssText = `flex:1 1 0;height:12px;background:${bg};border-radius:${edge};transition:height .12s`;
          cell.append(h);
          return h;
        };
        // While its message is on the way the state before it still holds: a loop that lasts stays red without a break.
        const holds = prevLoop && share > 0;
        const message = half(holds ? c.problem : c.none, "3px 0 0 3px"), state = half(color, "0 3px 3px 0");
        message.style.boxShadow = `inset 0 0 0 1px ${c.step}`;
        cells.push([from, to, cell, message, state]);
        prevLoop = share > 0;
      } else {
        cell.style.cssText = `flex:1 1 0;min-width:0;height:12px;background:${strength < 1 ? `color-mix(in srgb, ${color} ${Math.round(100 * strength)}%, ${c.step})` : color}`;
        cells.push([from, to, cell]);
      }
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
    timeline.dataset.single = single ? "1" : "";
    if (!single) {
      cursor = document.createElement("span");
      cursor.style.cssText = `position:absolute;top:0;bottom:0;width:3px;border-radius:2px;background:${c.ring};box-shadow:0 0 0 2px ${c.page};pointer-events:none`;
      timeline.append(cursor);
    }
    timeline.setAttribute("aria-valuemax", total);
    moveCursor();
    placeMarks();
  }
  // Numbered circles above the timeline at the key moments, in the proportion scrubbing uses, so that they
  // stand right on a dense timeline too. One that would cover the one before moves aside.
  const marks = root.querySelector("[data-marks]");
  function placeMarks() {
    marks.replaceChildren();
    const total = most();
    if (!total || cells.length < 2) return;
    const box = marks.getBoundingClientRect(), first = cells[1][2].getBoundingClientRect(), last = cells[cells.length - 1][2].getBoundingClientRect();
    const span = last.right - first.left, size = 24;
    let previous = -Infinity;
    moments.forEach((m, k) => {
      // Above the state half of its step: a key moment is a state.
      let x = first.left - box.left + ((m.step - 0.25) / total) * span;
      x = Math.max(x, previous + size + 2);
      previous = x;
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = k + 1;
      b.setAttribute("aria-label", `Key moment ${k + 1}, step ${m.step}`);
      b.dataset.step = m.step;
      b.className = `absolute top-0 grid size-6 -translate-x-1/2 place-content-center rounded-full text-xs font-medium tabular-nums ring-offset-1 ring-uoft-700 dark:ring-uoft-300 dark:ring-offset-slate-900 ${
        m.problem ? "bg-rose-600 text-white dark:bg-rose-400 dark:text-slate-900" : m.ok ? "bg-emerald-600 text-white dark:bg-emerald-400 dark:text-slate-900" : "bg-slate-200 text-slate-700 hover:bg-slate-300 dark:bg-slate-700 dark:text-slate-200"}`;
      b.style.left = `${x}px`;
      b.onclick = () => { stop(); go(m.step); };
      marks.append(b);
    });
    markCurrent();
  }
  // The circle of the moment shown wears a ring.
  function markCurrent() {
    const m = current();
    for (const b of marks.children) b.classList.toggle("ring-2", !!m && Number(b.dataset.step) === m.step);
  }

  // Where the page stands: step and phase. Short runs raise the half of the phase shown, long ones put the
  // line where it stands, a quarter into a step for its message, three quarters for its state.
  function moveCursor() {
    const t = traces.right;
    if (!t || !cells.length) return;
    const total = most(), single = timeline.dataset.single === "1", msg = inMessage();
    let mark = null;
    if (step === 0) mark = cells[0][2];
    else if (single) { const c = cells.find(([from, to]) => step > from && step <= to); mark = c ? c[msg ? 3 : 4] : null; }
    if (cursor) {
      cursor.hidden = step === 0;
      if (step > 0) {
        const first = cells[1][2], last = cells[cells.length - 1][2];
        const span = last.offsetLeft + last.offsetWidth - first.offsetLeft;
        cursor.style.left = `${first.offsetLeft + ((step - (msg ? 0.75 : 0.25)) / total) * span - 1.5}px`;
      }
    }
    if (mark !== active) {
      if (active) active.style.height = "12px";
      if (mark) mark.style.height = "20px";
      active = mark;
    }
    timeline.setAttribute("aria-valuenow", step);
    timeline.setAttribute("aria-valuetext", `step ${step} of ${total}${step ? (msg ? ", its message" : ", the state after it") : ""}${t.problem && step === t.problem.at ? ", the problem" : ""}`);
  }

  const most = () => (traces.right ? traces.right.steps.length : 0);

  const cap = (x) => x.charAt(0).toUpperCase() + x.slice(1);
  const without = (st) => st.routers.map((r, i) => (r.best === null && !r.waits ? i : -1)).filter((i) => i >= 0);

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
      const forms = loopNow && !loopBefore;
      if (forms) { focusOn = s.loop[0]; weight = Math.max(weight, 3); }
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
      // Short, to be told aloud: iBGP named, as it hides where a route comes from, and why a router switches.
      const best = (i) => (s.routers[i].in || []).find((x) => x.fate === "best");
      const over = (i) => (best(i) && best(i).over === "ibgp" ? ` from ${best(i).from} over iBGP` : "");
      for (const i of learn) { said.push(`router ${i} learns ${route(s.routers[i].best)}${over(i)}`); weight = Math.max(weight, 1); }
      for (const i of move) {
        // The path says enough: why it prefers it stands in the router's table.
        said.push(`router ${i} switches to the route ${route(s.routers[i].best)}${over(i)}`);
        weight = Math.max(weight, 1);
      }
      // OBGP offers the worst path it admitted, which may differ from the one it uses: told where the offer changes so.
      // Only where the offer is one path for every neighbor and paths compare as they are: pure OBGP modes with
      // one table, no confederation, whose segments the offer and the table write differently.
      if (PURE_OBGP.includes(t.mode) && !(inst.confeds || []).length) s.routers.forEach((r, i) => {
        const was = prev ? prev.routers[i] : null;
        const differs = (x) => x && x.exported && x.best && !same(x.exported, x.best);
        if (differs(r) && !(differs(was) && same(was.exported, r.exported))) {
          said.push(`router ${i} offers ${route(r.exported)}, not the route it uses`);
          weight = Math.max(weight, 1);
        }
      });
      if (lose.length) { said.push(`${routers(lose)} lose${lose.length > 1 ? "" : "s"} ${lose.length > 1 ? "their" : "its"} route`); focusOn = lose[0]; weight = Math.max(weight, 2); }
      if (waits.length) { said.push(`${routers(waits)} wait${waits.length > 1 ? "" : "s"} for a route refresh`); focusOn = waits[0]; weight = Math.max(weight, 2); }
      if (back.length) { said.push(`${routers(back)} ${back.length > 1 ? "have" : "has"} a route again`); weight = Math.max(weight, 1); }
      // The cause first, then the loop it makes.
      if (forms) said.push(`so ${routers(s.loop)} send packets to each other`);
      if (!everyone && !forms && k !== end && !out.some((m) => m.event) && s.routers.every((r) => r.best !== null)) {
        everyone = true;
        said.push("every router has a route"); weight = Math.max(weight, 2);
      }
      const problem = t.problem && t.problem.at === k;
      if (k === end) {
        const none = without(s), gone = steps.filter((x) => x.kind === "event").pop()?.event.kind === "withdraw";
        // A run that never rests ends on that alone, without the change of its last step.
        if (!t.result.converged) said.length = 0;
        said.push(!t.result.converged ? `still not at rest after ${t.cut || end} steps${repeats ? ", the moments above repeat" : ""}${t.cut ? `, the first ${end} shown` : ""}`
          : gone && none.length === n ? "at rest no router has a route, as the prefix is gone"
          : s.loop && s.loop.length ? `at rest ${routers(s.loop)} send packets to each other`
          : none.length ? `at rest ${routers(none)} ${none.length > 1 ? "have" : "has"} no route`
          : t.problem ? "at rest every router has a route" : "at rest every router has a route and no packets loop, all good");
        if (none.length) focusOn = none[0];
        weight = 3;
      }
      if (problem) { weight = 4; const hit = [...hitOf(t.mode)]; if (hit.length && !said.length) said.push(`${routers(hit)} show the problem`); }
      // A run that never comes to rest goes round: a moment told once is enough.
      const text = cap(said.join(", "));
      // A moment again: the same moment, at this step too, so that the page follows the loop round.
      if (said.length && told.has(text) && k !== end && !problem) { repeats = true; out.find((m) => m.text === text)?.again.push(k); }
      else if (said.length) { told.add(text); out.push({ step: k, text, router: focusOn, weight, problem, event: s.kind === "event", again: [],
        ok: k === end && t.result.converged && !t.problem && !(s.loop && s.loop.length)
          && (!without(s).length || steps.filter((x) => x.kind === "event").pop()?.event.kind === "withdraw") }); }
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
  // The key moment reached: its state shown, not only its message on the way.
  // In a run that goes round, a moment is reached again each time it repeats: the latest reached is the current one.
  const reached = (m) => [m.step, ...(m.again || [])].filter((k) => k < step || (k === step && !inMessage())).pop() ?? -1;
  const current = () => moments.reduce((best, m) => (reached(m) >= 0 && (!best || reached(m) > reached(best)) ? m : best), null) || undefined;
  function showMoments() {
    const now = current();
    root.querySelector("[data-moments]").innerHTML = moments.map((m, k) => `<li><button type="button" data-step="${m.step}"
      class="flex w-full items-start gap-2.5 rounded-md px-2 py-3 text-left sm:py-1.5 ${m === now ? "bg-slate-100 font-medium dark:bg-white/10" : "hover:bg-slate-50 dark:hover:bg-white/5"}">
      <span class="mt-0.5 grid size-5 shrink-0 place-content-center rounded-full text-xs tabular-nums ${m.problem ? "bg-rose-600 text-white dark:bg-rose-400 dark:text-slate-900" : m.ok ? "bg-emerald-600 text-white dark:bg-emerald-400 dark:text-slate-900" : m === now ? "bg-uoft-700 text-white dark:bg-uoft-300 dark:text-slate-900" : "bg-slate-200 dark:bg-slate-700"}">${k + 1}</span>
      <span class="${m.problem ? "text-rose-700 dark:text-rose-300" : m.ok ? "text-emerald-700 dark:text-emerald-300" : ""}">${m.text}</span></button></li>`).join("")
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

  // Under the graph the key moment it shows, numbered, as one would say it.
  const caption = root.querySelector("[data-caption]");
  // What changed at router r with message k: learns, switches, loses, or keeps its route.
  function change(t, k) {
    const st = t.steps[k - 1];
    if (st.kind === "event") return "";
    const r = st.to, now = st.routers[r].best, then = k > 1 ? t.steps[k - 2].routers[r].best : null;
    if (same(now, then)) return `<span class="muted">Router ${r} keeps ${now === null ? "no route" : `its route ${esc(route(now))}`}</span>`;
    if (now === null) return `Router ${r} loses its route`;
    return then === null ? `Router ${r} learns ${esc(route(now))}` : `Router ${r} switches to ${esc(route(now))}`;
  }
  function showCaption() {
    const m = current(), t = traces.right;
    if (!t) { caption.textContent = ""; return; }
    // The message phase says the message, or the event from outside.
    if (inMessage()) {
      const st = t.steps[step - 1];
      caption.innerHTML = st.kind === "event" ? `Event: ${event(st.event)}` : `<span class="muted">Message ${step}:</span> ${messageLine(t, step).replace(/^<span[^>]*>\d+<\/span> /, "").replace(/, <span class="[^"]*">[^<]*<\/span>$/, "")}`;
      return;
    }
    // The state phase: a key moment where there is one, else what the message changed.
    if (step && !(m && reached(m) === step)) { caption.innerHTML = change(t, step); return; }
    // Only at step 0 the start is said, between it and the first key moment the line is empty.
    if (!m) { caption.innerHTML = step === 0 ? '<span class="muted">Before the first message: only the origin has the prefix.</span>' : ""; return; }
    const off = "";
    // The moment of the problem in its colour, as in the list and on the timeline.
    caption.innerHTML = `<span class="${
      m.problem ? "text-rose-700 dark:text-rose-300" : m.ok ? "text-emerald-700 dark:text-emerald-300" : ""}">${m.text}</span>${off}`;
  }

  function show() {
    step = Math.min(step, most());
    // The phase counts too: each step is its message and then its state.
    counter.textContent = step === 0 ? `start / ${most()}` : `${inMessage() ? "message" : "state"} ${step} / ${most()}`;
    showCaption();
    markCurrent();
    draw("right");
    moveCursor();
    showMoments();
    drawWindows();
  }

  // Scrubbing: the step from where the pointer stands along the cells, in proportion, so that every step can
  // be reached on a long run too. Left of the cells is step 0. Read at most once a frame, drawn only when the step changes.
  let wanted = null, scrub = 0;
  const pick = (e) => {
    if (!cells.length) return;
    const first = cells[1]?.[2] || cells[0][2], last = cells[cells.length - 1][2];
    const left = first.getBoundingClientRect().left, right = last.getBoundingClientRect().right;
    const total = most();
    // In halves: the left half of a step its message, the right half its state.
    wanted = e.clientX < left ? 0 : Math.max(1, Math.min(2 * total, Math.ceil(((e.clientX - left) / Math.max(1, right - left)) * 2 * total)));
    scrub ||= requestAnimationFrame(() => {
      scrub = 0;
      if (wanted === null) return;
      const to = Math.ceil(wanted / 2), as = wanted && wanted % 2 ? "message" : "state";
      if (to !== step || as !== phase) { step = to; phase = as; show(); }
    });
  };
  timeline.addEventListener("pointerdown", (e) => { e.preventDefault(); stop(); timeline.setPointerCapture(e.pointerId); pick(e); });
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
    // The verdict of this mode, said outright: the problem of the case, or none.
    const bad = affected.has(t.mode);
    sec.querySelector("[data-state]").innerHTML = `<span class="mr-1.5 rounded px-1.5 py-0.5 font-medium ${bad
      ? "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300" : "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"}">${bad ? "Problem" : "No problem"}</span>${t.cut ? `${t.cut} messages, the first ${messages} shown` : `${messages} messages`}, ${t.result.converged ? "comes to rest" : "never at rest"}`;
    if (side === "right") {
      moments = keyMoments(t);
      // Following one router's packets matters only where a router forwards by where a packet came from, as under NS-BGP:
      // elsewhere the arrows of every router's first hop already draw each whole way.
      if (followSelect) {
        const byIngress = t.steps.some((x) => (x.routers || []).some((r) => r.ingress));
        followSelect.classList.toggle("hidden", !byIngress);
        if (!byIngress) followSelect.value = "";
      }
      // One sentence under the title: why it happens, else what happens.
      if (t.problem) {
        // The title says what happens: one grey line under it, why, else what happens in more detail.
        document.querySelector("[data-why]").textContent = why(t) || t.problem.text;
      }
      // Open at step 0, before the first message: the story is told from its start.
      step = 0;
      buildTimeline();
    }
    show();
  }

  const play = root.querySelector("[data-act=play]");
  // The slider snaps to these, its label says the one chosen.
  const SPEEDS = [0.5, 1, 2, 4, 8, 16], slider = root.querySelector("[data-speed]");
  const speed = () => SPEEDS[Number(slider.value)] ?? 1;
  const playing = (on) => { play.innerHTML = `${UI.icon(on ? "pause" : "play")}<span>${on ? "Pause" : "Play"}</span>`; };
  const stop = () => { clearInterval(timer); timer = null; playing(false); };
  const loop = root.querySelector("[data-act=loop]");
  const looping = () => loop.getAttribute("aria-pressed") === "true";
  // Play goes message by message, at 1× one a second, as the arrows beside it step.
  // At the end a loop starts over, else playing stops.
  // Half a step on or back: message, then state. A jump lands on a state.
  const half = (by) => {
    if (by > 0) {
      if (phase === "message") phase = "state";
      else if (step < most()) { step++; phase = "message"; }
    } else if (phase === "message") { step--; phase = "state"; } else if (step > 0) phase = "message";
    show();
  };
  const tick = () => {
    clearInterval(timer);
    timer = setInterval(() => (step < most() || phase === "message" ? half(1) : looping() ? go(0) : stop()), 500 / speed());
  };
  const go = (to) => { step = Math.max(0, Math.min(most(), to)); phase = "state"; show(); };
  slider.addEventListener("input", () => {
    root.querySelector("[data-speed-label]").textContent = speed() === 0.5 ? "½×" : `${speed()}×`;
    if (timer) tick();
  });
  // The arrows step one message, the key moments are picked in their list.
  root.querySelector("[data-act=prev]").onclick = () => { stop(); half(-1); };
  root.querySelector("[data-act=next]").onclick = () => { stop(); half(1); };
  loop.onclick = () => loop.setAttribute("aria-pressed", !looping());
  play.onclick = () => {
    if (timer) return stop();
    if (step >= most() && phase === "state") { step = 0; phase = "state"; }  // from the start once the end was shown
    playing(true);
    tick();
  };
  document.addEventListener("keydown", (e) => {
    if (e.target.closest("input, select, textarea, button, summary, [role=slider]")) return;
    if (e.key === "ArrowRight") { stop(); half(1); }
    if (e.key === "ArrowLeft") { stop(); half(-1); }
  });
  // A menu whose mode has the problem is red, as are such modes in its list (ui.js carries both over).
  const mark = (select) => {
    const bad = select.selectedOptions[0]?.hasAttribute("data-problem");
    select.classList.toggle("text-rose-700", bad), select.classList.toggle("dark:text-rose-300", bad), select.classList.toggle("border-rose-400", bad);
  };
  for (const side of ["right"]) {
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
    // One window per router or link: its table at the state shown, with the message on its way above it.
    for (const w of windows.values()) {
      const i = w.target;
      const body = w.querySelector("[data-body]");
      const link = typeof i === "string" ? i.split("-").map(Number) : null;
      const shown = Math.min(step, t ? t.steps.length : 0), st = t && step ? t.steps[step - 1] : null;
      const here = st && st.kind !== "event" && (link ? link.includes(st.from) && link.includes(st.to) : st.from === i || st.to === i);
      const before = inMessage() ? shown - 1 : shown;
      const message = inMessage() && here ? `<p class="mb-2 border-b border-slate-900/10 pb-2 dark:border-white/10">${messageLine(t, step, link ? undefined : i).replace(/, <span class="[^"]*">[^<]*<\/span>$/, "")}</p>` : "";
      body.innerHTML = message + (!(t && before) ? '<p class="muted text-xs">Before the first message.</p>'
        : link ? linkState(t, before, link[0], link[1]) : ribRows(t, before, i));
    }
  }
  // A router's table pops up beside the router clicked, inside the page's width.
  function openWindow(i, near) {
    const key = String(i);
    if (windows.has(key)) return windows.get(key).focus();
    const w = document.createElement("div");
    w.target = i;
    w.tabIndex = -1;
    // On the page, not the screen: it stays where it was put while the page scrolls.
    w.className = "card absolute z-40 w-[26rem] max-w-[90vw] p-0 shadow-lg";
    w.style.left = `${scrollX + (desktop ? 120 + 30 * windows.size : 8)}px`;
    w.style.top = `${scrollY + (desktop ? 120 : 72) + 30 * windows.size}px`;
    w.innerHTML = `<div data-drag class="flex cursor-move items-center gap-2 border-b border-slate-900/10 px-3 py-1.5 text-sm select-none dark:border-white/10">
      <b>${typeof i === "string" ? `Link ${i.replace("-", "–")}` : `Router ${i}`}</b><span class="mr-auto"></span>
      <button type="button" data-close class="btn btn-icon size-7 border-transparent shadow-none" aria-label="Close">✕</button></div>
      <div data-body class="p-2 text-sm"></div>`;
    w.querySelector("[data-close]").onclick = () => { windows.delete(key); w.remove(); show(); };
    const bar = w.querySelector("[data-drag]");
    // Dragged by a transform, set once a frame: the window follows the pointer without laying out its table anew.
    bar.style.touchAction = "none";
    w.style.willChange = "transform";
    let ox = 0, oy = 0, frame = 0;
    bar.addEventListener("pointerdown", (e) => {
      if (e.target.closest("button")) return;
      e.preventDefault();
      const sx = e.clientX - ox, sy = e.clientY - oy;
      bar.setPointerCapture(e.pointerId);
      const move = (m) => {
        // Never past the left or top edge of the page.
        ox = Math.max(-w.offsetLeft, m.clientX - sx);
        oy = Math.max(-w.offsetTop, m.clientY - sy);
        frame ||= requestAnimationFrame(() => { frame = 0; w.style.transform = `translate3d(${ox}px, ${oy}px, 0)`; });
      };
      const end = () => { bar.removeEventListener("pointermove", move); bar.removeEventListener("lostpointercapture", end); };
      bar.addEventListener("pointermove", move);
      bar.addEventListener("lostpointercapture", end);
    });
    document.body.append(w);
    if (near) {
      const room = scrollX + document.documentElement.clientWidth - w.offsetWidth - 8;
      w.style.left = `${Math.max(scrollX + 8, Math.min(near.pageX + 18, room))}px`;
      w.style.top = `${near.pageY + 18}px`;
    }
    windows.set(key, w);
    show();
  }
  root.querySelector("[data-side=right] [data-graph]").addEventListener("click", (e) => {
    // A router's table, or what flows on a link, opens as a window of its own, also on a phone.
    const g = e.target.closest("[data-router]"), link = e.target.closest("[data-link]");
    if (g) openWindow(Number(g.dataset.router), e);
    else if (link) openWindow(link.dataset.link, e);
  });
  load("right");
  document.addEventListener("lab:theme", () => { buildTimeline(); show(); });
  new ResizeObserver(() => { moveCursor(); placeMarks(); }).observe(timeline);  // the line stands at a cell's middle, in pixels

  // Above the graphs, in one line: what is special about this network, and why it lies outside the proofs' model.
  const setup = [
    ...several.map(([asn, rs]) => `AS ${asn} is ${routers(rs)}${(inst.ibgp || []).some((x) => asNumber(x.as) === Number(asn)) ? `, ${routers((inst.ibgp.find((x) => asNumber(x.as) === Number(asn)).reflectors))} reflect${inst.ibgp.find((x) => asNumber(x.as) === Number(asn)).reflectors.length > 1 ? "" : "s"} routes` : ", full iBGP mesh"}`),
    ...(inst.confeds || []).map((c) => `AS ${c.members.map(asNumber).join(" and ")} form confederation ${c.id}`),
    ...[...servers].map((r) => `router ${r} is a route server`),
  ];
  // The legend lists only what this network has, as the lab's graphs do.
  const present = { aim: finding.kind === "loop" || finding.kind === "transient-loop", peers: (inst.peers || []).length > 0, ibgp: several.length > 0, frame: several.length > 0 || (inst.confeds || []).length > 0, rr: reflectors.size > 0, rs: servers.size > 0 };
  for (const item of document.querySelectorAll("[data-key]")) item.hidden = !present[item.dataset.key];
  // The network and its policies, one kind of fact a row, after the rows the page gives (modes, family, how often).
  const facts = [];
  if (outside && root.dataset.proof === "outside its model") facts.push(["Proofs", `outside their model: ${outside}`]);
  for (const x of setup) facts.push(["Special", x]);
  facts.push(["Routers", `${n}, numbered 0 to ${n - 1}`], ["Origin", `router ${origin}`]);
  // ASes of several routers, reflectors and route servers stand in the line above the graphs, not again here.
  const rel = [
    ...(inst.customers || []).map(([p, cst]) => `${cst} is a customer of ${p}`),
    ...(inst.peers || []).map(([a, b]) => `${a} and ${b} are peers`),
    ...(inst.siblings || []).map(([a, b]) => `${a} and ${b} are siblings`),
  ];
  // One relation a line, as the filters: the label once, the rows under it.
  for (const r of rel) facts.push(["Relations", r]);
  if ((inst.leakers || []).length) facts.push(["Leaks", `${routers(inst.leakers)} pass every route to every neighbor`]);

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
  document.querySelector("[data-policies]").insertAdjacentHTML("beforeend", facts.map(([k, v], i) =>
    `<dt class="muted">${i && facts[i - 1][0] === k ? "" : k}</dt><dd>${cap(v)}</dd>`).join(""));
})();
