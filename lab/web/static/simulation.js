// Simulation: one finding of the simulator, in the mode chosen, first one
// with the problem. The map (sim-map.js) tells the run step by step. Here:
// loading a run, the verdict beside the mode, the line under the title that
// says why it happens, and the network with its policies below the map.
(() => {
  const root = document.getElementById("sim");
  if (!root) return;
  const example = JSON.parse(document.getElementById("sim-example").textContent);
  const inst = example.instance, finding = example.finding;
  const n = inst.routers, origin = inst.origin ?? 0;
  // The modes that show the problem on this network, each with the routers it affects.
  const perMode = JSON.parse(root.dataset.modes), affected = new Set(Object.keys(perMode));
  const hitOf = (mode) => new Set(perMode[mode]?.routers || []);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

  // AS numbers to routers, as the simulator assigns them: AS index i has the
  // number 65001 + i unless asns gives it, a router the AS index inst.as gives,
  // or its own. An AS of several routers stays an AS.
  const asIndex = (r) => (inst.as && inst.as.length ? inst.as[r] : r);
  const asNumber = (a) => (inst.asns && a < inst.asns.length ? inst.asns[a] : 65001 + a);
  const members = {};
  for (let r = 0; r < n; r++) (members[asNumber(asIndex(r))] ||= []).push(r);
  // An AS of one router named with its router, as the routes name it: "AS 65004 (router 3)".
  const asName = (asn) => (members[asn] && members[asn].length === 1 ? `AS ${esc(asn)} (r${members[asn][0]})` : `AS ${esc(asn)}`);
  const hop = (asn) => (members[asn] && members[asn].length === 1 ? `r${members[asn][0]}` : asn === 0 ? "the confederation" : `AS ${asn}`);
  const poison = inst.origin_poison || [];
  // An aggregate's AS_SET ends every path: the facts name it once, the routes leave it out.
  const originSet = [...(inst.origin_set || [])].sort((a, b) => a - b);
  const route = (p) => {
    if (p === null || p === undefined) return "no route";
    const s = originSet.length;
    if (s && p.length >= s && same([...p.slice(p.length - s)].sort((a, b) => a - b), originSet)) p = p.slice(0, p.length - s);
    if (!p.length) return "own prefix";
    // The origin puts the ASes it poisons before its own: they stand in the path, not on it.
    const k = poison.length;
    const poisoned = k && p.length > k && poison.every((a, j) => p[p.length - 1 - k + j] === a);
    const passed = poisoned ? [...p.slice(0, p.length - 1 - k), p[p.length - 1]] : p;
    // An AS prepended stands once, with how often it repeats: a route that seems to loop does not.
    const runs = [];
    for (const a of passed) runs.length && runs[runs.length - 1][0] === a ? runs[runs.length - 1][1]++ : runs.push([a, 1]);
    const prepended = runs.filter(([, c]) => c > 1).map(([a, c]) => `, ${hop(a)} prepended ${c - 1}×`).join("");
    // A route never breaks across lines: a no-break space after "via", word joiners around the arrows.
    return "via\u00a0" + runs.map(([a]) => hop(a)).join("\u2060→\u2060") + prepended + (poisoned ? `, poisons AS ${poison.join(", ")}` : "");
  };
  // A path with a confederation segment as one 0, as GoBGP lists it and older traces give it, to compare paths of
  // either form, and the full path a neighbor sent that matches one of an older trace.
  const confedMembers = new Set((inst.confeds || []).flatMap((c) => c.members.map(asNumber)));
  const listOf = (p) => { let k = 0; while (p && k < p.length && confedMembers.has(p[k])) k++; return k ? [0, ...p.slice(k)] : p; };
  const full = (r, p) => (p && p.includes(0) ? ((r.in || []).find((x) => x.path && same(listOf(x.path), p)) || {}).path || p : p);
  // The pure OBGP modes of lab/modes.py: one table, every router OBGP.
  const PURE_OBGP = JSON.parse(document.getElementById("pure-modes").textContent).filter((m) => m !== "bgp");
  // Routers as the map names them: r1, "r1, r2 and r3".
  const routers = (list) => (list.length === 1 ? `r${list[0]}` : `${list.slice(0, -1).map((i) => `r${i}`).join(", ")} and r${list[list.length - 1]}`);
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const has = (list, p) => list.some((q) => same(q, p));
  const plain = (mode) => mode === "bgp" || mode === "bgp-pn";  // BGP's decision, with one table or one per neighbor

  // Roles of the routers: route reflectors and their clients, route servers,
  // the ASes of several routers and the confederations.
  const reflectors = new Set((inst.ibgp || []).flatMap((x) => x.reflectors || []));
  const servers = new Set(inst.route_servers || []);
  const several = Object.entries(members).filter(([, rs]) => rs.length > 1);
  const confedOf = (r) => (inst.confeds || []).find((c) => c.members.includes(asIndex(r)));

  // Why router i sends its packets where it does, in a few words: "r2 prefers r4's route but reaches r4 only through r1".
  function reason(r, i) {
    const best = (r.in || []).find((x) => x.fate === "best"), others = (r.in || []).filter((x) => x.fate === "admitted");
    // A route server passes on its clients' routes: the route named, not the server's.
    const whose = !best ? "its route" : best.over === "rs" ? `the route ${route(r.best)} from route server r${best.from}` : `r${best.from}'s route`;
    const knows = !best ? `r${i} holds ${route(r.best)}` : others.length ? `r${i} prefers ${whose}` : `r${i} only knows ${whose}`;
    const to = forwardOf(r, i);
    return to !== r.next_hop && r.next_hop >= 0 ? `${knows} but reaches r${r.next_hop} only through r${to}` : knows;
  }

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
      down: `link r${a}–r${b} fails`,
      up: `link r${a}–r${b} comes back`,
      prepend: `r${a} prepends ${v}× towards r${b}`,
      "prepend-all": `r${a} prepends ${v}× towards all`,
      "local-pref": `r${b} sets local preference ${e.value ? v : "back"} for routes from r${a}`,
      igp: `IGP cost of link r${a}–r${b} becomes ${v}`,
      "deny-export": `r${a} ${on} filtering what it sends r${b}`,
      "deny-import": `r${b} ${on} rejecting what r${a} sends`,
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

  // The routers that show the problem at each step, for the map to mark: those waiting or without their route for a
  // moment while it happens on the way, the routers of the problem from their last change on when it shows at rest,
  // and in a run without rest those of the problem in its second half. A loop the map finds itself.
  function marksOf(t) {
    const steps = t.steps, end = steps.length, hit = [...hitOf(t.mode)], last = steps[end - 1];
    const marks = steps.map(() => []);
    if (!end || !affected.has(t.mode)) return marks;
    const had = new Array(n).fill(false);
    steps.forEach((s, k) => s.routers.forEach((r, i) => {
      const gone = had[i] && r.best === null;
      if (r.best !== null) had[i] = true;
      if (finding.kind === "transient-blocked" && gone && r.waits) marks[k].push(i);
      if (finding.kind === "transient-hole" && gone && last.routers[i].best !== null) marks[k].push(i);
    }));
    if (finding.kind.startsWith("transient-") || finding.kind === "loop") return marks;
    const changed = (k, i) => !same(steps[k].routers[i].best, steps[k - 1].routers[i].best) || steps[k].routers[i].forward !== steps[k - 1].routers[i].forward;
    if (finding.kind === "no-convergence") {
      // From where the run repeats itself, else its second half: the routers of the problem, else those that still change.
      const from = t.result && t.result.cycle ? Math.max(1, t.result.cycle.from - 1) : Math.max(1, Math.floor(end / 2));
      const busy = hit.length ? hit : [...Array(n).keys()].filter((i) => steps.slice(from).some((_, j) => from + j > 0 && changed(from + j, i)));
      for (let k = from; k < end; k++) marks[k].push(...busy);
      return marks;
    }
    // At rest: from the last change of any router on, when the network has come to rest.
    let from = 0;
    for (let k = 1; k < end; k++) if ([...Array(n).keys()].some((i) => changed(k, i))) from = k;
    for (let k = from; k < end; k++) marks[k].push(...hit);
    return marks;
  }

  // Why the problem happens, in a few sentences from the run's own
  // state at the step it shows: what the routers around it hold and offer,
  // and the policies of the network on the way. Facts only, no guesses.
  // A router's neighbors over its links, in order.
  const neighbors = (i) => [...new Set(inst.links.flatMap(([a, b]) => (a === i ? [b] : b === i ? [a] : [])))].sort((a, b) => a - b);
  // Whether an event set a filter on from a to b by step k: deny-export at a for b, deny-import at b for a.
  const filterOn = (t, k, kind, a, b) => t.steps.slice(0, k).filter((x) => x.kind === "event" && x.event.kind === kind
    && (x.event.from ?? 0) === a && (x.event.to ?? 0) === b).reduce((_, x) => !!x.event.value, false);
  // Why router i sends neighbor j nothing at step k although it has a route, where the simulator says only that it has
  // nothing to offer: over iBGP a route from one iBGP peer goes to no other, a table per neighbor may hold none for j.
  function nothingFor(t, k, i, j) {
    const r = t.steps[k - 1].routers[i];
    if (r.best === null) return "";
    // What it offers: BGP the route it uses, OBGP the worst path it admitted, which may come from elsewhere.
    const best = (r.in || []).find((x) => x.fate === "best"), link = (r.in || []).find((x) => x.from === j);
    const worst = !plain(t.mode) && r.exported && (r.in || []).find((x) => x.path && ["best", "admitted"].includes(x.fate) && same(listOf(x.path), listOf(r.exported)));
    const src = worst || best, other = src && src !== best ? `it offers ${route(src.path)}, the worst path it admitted, which` : "";
    if (src && src.from === j) return other ? `${other} came from r${j}` : "back to its source";
    if (link && link.over === "ibgp") return src && src.over === "ibgp"
      ? `${other || "its route"} came over iBGP${reflectors.has(i) ? `, and neither r${src.from} nor r${j} is its client` : " and goes to no other iBGP peer"}` : "";
    if (filterOn(t, k, "deny-export", i, j)) return "its export filter drops it";
    if (!t.mode.endsWith("-pn")) return "";
    // A table per neighbor holds no path from that neighbor, nor one through its AS.
    const paths = (r.in || []).filter((x) => x.path && ["best", "admitted"].includes(x.fate) && x.from !== j).map((x) => x.path);
    const theirs = [asNumber(asIndex(j)), ...(confedOf(j) ? [confedOf(j).id] : [])];
    // The policy towards j that keeps the others out of that table.
    const x = (inst.sessions || []).find((y) => (y.from ?? 0) === i && (y.to ?? 0) === j) || {}, rel = relationOf(i, j);
    const tagged = (inst.sessions || []).some((y) => y.tag === `0:${asNumber(asIndex(j))}`);
    const note = x.deny_via ? `, as it sends r${j} no path through ${asName(x.deny_via)}`
      : ["provider", "peer"].includes(rel) ? `, as r${j} is its ${rel} and gets only customer routes`
      : tagged ? `, as a community keeps tagged paths from r${j}` : "";
    return paths.length && paths.every((p) => p.some((a) => theirs.includes(a))) ? `every path it holds runs through r${j}'s AS`
      : !paths.length ? `its only paths come from r${j}` : `no path in its table for r${j}${note}`;
  }
  // A path's length as OBGP's order counts it: the confederation's hops and an aggregate's AS_SET as one hop at most.
  const hopsOf = (p) => {
    let q = listOf(p) || [];
    if (q[0] === 0) q = q.slice(1);
    const s = originSet.length;
    return s && q.length >= s && same([...q.slice(q.length - s)].sort((a, b) => a - b), originSet) ? q.length - s + 1 : q.length;
  };
  // Why an OBGP router with one table sets a path aside: its order admits only a path better than the worst it admitted,
  // which it offers, else a withdrawal through the path's ASes set it aside. Without a route it waits for a route refresh.
  function asideWhy(t, r, path) {
    if (plain(t.mode) || t.mode.endsWith("-pn")) return "";
    if (r.waits) return "until a route refresh brings it again";
    const worst = full(r, r.exported);
    if (!worst || !path) return "";
    const a = hopsOf(path), b = hopsOf(worst);
    return a > b ? "longer than the path it offers" : a === b ? "as long as the path it offers, which wins" : "a withdrawal through its ASes set it aside";
  }
  // The route behind a path a router sends, without its own AS: the route as the rest of the page names it.
  const sentRoute = (x, p) => named(behind(x, p || []));
  const named = (p) => (route(p) === "own prefix" ? "its own prefix" : route(p));
  function why(t) {
    if (!t.problem || !t.problem.at) return "";
    const at = t.problem.at, s = t.steps[at - 1], bgp = example.results && example.results.bgp;
    // Per router without a route: what each neighbor with one offers it, and what stops it. BGP's offer beside.
    const offer = (x, h) => {
      // From the run itself: what router x sends router h, or why not, and what h makes of it.
      const rx = s.routers[x], sent = (rx.out || []).find((o) => o.to === h), got = (s.routers[h].in || []).find((o) => o.from === x);
      // At rest, BGP's offer beside: BGP offers the route it uses, in full where the offer lists a confederation's segment as 0.
      const atRest = ["unreachable", "black-hole"].includes(finding.kind) && t.mode !== "bgp";
      const theirs = atRest && bgp && bgp.exported && bgp.exported[x] && !same(bgp.exported[x], rx.exported)
        ? ` BGP would offer ${route(bgp.best && same(listOf(bgp.best[x]), listOf(bgp.exported[x])) ? bgp.best[x] : full(rx, bgp.exported[x]))}.` : "";
      const offered = named(full(rx, rx.exported) || rx.best), only = route(rx.best) === "own prefix" ? "" : "only ";
      if (sent && !sent.path && sent.not === "nothing to offer") {
        const none = nothingFor(t, at, x, h);
        return none ? `r${x} ${only ? `uses ${route(rx.best)}` : "has the prefix"} but sends r${h} nothing: ${none}.${theirs}` : `r${x} has nothing to offer r${h}.${theirs}`;
      }
      if (sent && !sent.path) {
        // The rule behind it, concrete where the network says it.
        const x0 = (inst.sessions || []).find((y) => (y.from ?? 0) === x && (y.to ?? 0) === h) || {};
        const c = confedOf(h), path = full(rx, rx.exported) || [];
        const concrete = sent.not === "the export filter drops it" && x0.deny_via ? `but it sends r${h} no path through ${asName(x0.deny_via)}`
          : sent.not === "the relation forbids it" && relationOf(x, h) ? `but r${h} is its ${relationOf(x, h)} and gets only customer routes` : "";
        const stop = concrete || { "the export filter drops it": "and its export filter drops that", "the relation forbids it": `which it may not pass to r${h}`,
          "a community withholds it": `which a community keeps from r${h}`,
          "its AS is in the path": c && path.includes(c.id) ? `which runs through r${h}'s confederation ${c.id}` : `which runs through r${h}'s AS`,
          "back to its source": `which came from r${h}`, "the session is down": `but its link to r${h} is down` }[sent.not] || `but ${esc(sent.not)}`;
        return `r${x} offers ${only}${offered}, ${stop}.${theirs}`;
      }
      // A path sent and not yet delivered: the receiver still holds what came before, or nothing.
      if (sent && sent.path && !(got && same(got.path, sent.path))) {
        const comes = t.steps.findIndex((y, k) => k >= at && y.from === x && y.to === h && y.kind === "update");
        return `r${x} sends r${h} ${sentRoute(x, sent.path)}, which has not reached it yet${comes >= 0 ? ` and arrives at step ${comes + 1}` : ""}.${theirs}`;
      }
      const fate = got && got.fate !== "none" ? got.fate : "";
      const aside = fate === "set aside" ? asideWhy(t, s.routers[h], got.path) : "";
      // Hard pruning takes out every path through the ASes of one withdrawn: the withdrawal that did.
      const by = fate === "pruned" && t.steps.slice(0, at).map((y, k) => [y, k + 1]).reverse()
        .find(([y]) => y.kind === "withdraw" && y.to === h && y.from !== x && ((y.routers[h].in || []).find((o) => o.from === x) || {}).fate === "pruned");
      const told = { "set aside": `sets aside${aside ? `, ${aside}` : ""}`, filtered: "rejects with its import filter", loop: "rejects, as its own AS is in it",
        pruned: `pruned ${by ? `when r${by[0].from} withdrew a path through the same ASes at step ${by[1]}` : "after a withdrawal"}: hard pruning takes it back only once r${x} sends it anew`, dropped: "does not keep" }[fate];
      return `r${x} sends r${h} ${sentRoute(x, sent ? sent.path : rx.exported)}, which r${h} ${told || "does not admit"}.${theirs}`;
    };
    const nearOf = (h) => neighbors(h).filter((x) => s.routers[x].best !== null && s.routers[x].next_hop !== h);
    const lacking = (who) => who.map((h) => {
      const holding = neighbors(h).filter((x) => s.routers[x].best !== null), near = nearOf(h), through = holding.filter((x) => !near.includes(x));
      const back = through.length ? `${cap(routers(through))} reach${through.length > 1 ? "" : "es"} the prefix through r${h} itself.` : "";
      if (near.length) return [...near.map((x) => offer(x, h)), back].filter(Boolean).join(" ");
      return back || `No neighbor of r${h} has a route.`;
    }).join(" ");
    // What the step did that shows the problem: the event, a withdrawal and why its sender sent it, or the path that came.
    const trigger = () => {
      if (s.kind === "event") return `${cap(event(s.event))}.`;
      // Why it withdraws, unless what it offers now says so below.
      const said = nearOf(s.to).includes(s.from) ? "" : withdrawWhy(t, at);
      if (s.kind === "withdraw") return `r${s.from} withdraws its route from r${s.to}${said ? `: ${said}` : ""}.`;
      return "";
    };
    switch (finding.kind) {
      case "unreachable": case "black-hole":
        return lacking([...hitOf(t.mode)].filter((h) => s.routers[h].best === null).slice(0, 1));
      case "transient-hole": {
        // The routers that just lost their route, as analyse finds them.
        const before = at > 1 ? t.steps[at - 2] : null;
        const who = s.routers.map((r, i) => (r.best === null && before && before.routers[i].best !== null ? i : -1)).filter((i) => i >= 0);
        return [trigger(), lacking(who.slice(0, 1))].filter(Boolean).join(" ");
      }
      case "transient-blocked": {
        const w = s.routers.findIndex((r) => r.waits && r.best === null);
        if (w < 0) return "";
        const kept = (s.routers[w].in || []).filter((x) => x.fate === "set aside"), aside = kept.map((x) => x.path);
        if (!aside.length) return `r${w} lost its route and has no other. It waits for a refresh.`;
        // A withdrawal sets aside every path through the withdrawn one, refresh pruning; else OBGP's order keeps them out.
        const before = at > 1 ? ((t.steps[at - 2].routers[w].in || []).find((x) => x.from === s.from) || {}).path : null;
        const gone = s.kind === "withdraw" && s.to === w && before && before.length ? before : null;
        const through = (p) => gone && p.some((_, k) => same(p.slice(k, k + gone.length), gone));
        const list = kept.map((x) => `${route(x.path)} from r${x.from}`).join(" and ");
        if (aside.every(through)) return `r${w} lost its route ${route(gone)} and sets ${list} aside, as ${aside.length > 1 ? "they run" : "it runs"} through the path withdrawn. It waits for a refresh to get ${aside.length > 1 ? "them" : "it"} again.`;
        const offered = t.steps.slice(0, at - 1).map((x) => full(x.routers[w], x.routers[w].exported)).filter((p) => p !== null).pop();
        return `r${w} lost its route and sets ${list} aside, as OBGP admits only a path shorter than the one it offered last${offered ? ` (${route(offered)})` : ""}. It waits for a refresh.`;
      }
      case "transient-loop": case "loop": {
        const loop = s.loop && s.loop.length ? s.loop : [...hitOf(t.mode)];
        if (loop.length < 2) return "";
        // A route from a message its sender sent before it changed its own: the router acts on news that is old.
        // Any of the routes it offers counts (a route server offers several), and it must have offered it when it sent it.
        const offers = (r) => (r.out || []).some((o) => o.to === s.to && o.path && route(behind(s.from, o.path)) === route(behind(s.from, s.path)));
        const stale = s.kind === "update" && s.sent < at - 1 && !offers(s.routers[s.from]) && (!s.sent || offers(t.steps[s.sent - 1].routers[s.from]))
          ? `r${s.to} takes ${route(s.path)} from a message r${s.from} sent ${s.sent ? `at step ${s.sent}` : "at the start"}, before r${s.from}'s offer changed. ` : "";
        // Under NS-BGP a router sends a packet on the route it offers the router the packet came from: the loop told that way.
        if (s.routers.some((r) => r.ingress)) {
          const walk = ingressLoop(s, loop);
          if (walk) return stale + walk;
        }
        // Short, one clause per router of the loop: what it knows or prefers, and the detour to its next hop.
        const chain = [];
        for (let i = loop[0], k = 0; k < loop.length && !chain.some((x) => x.i === i); k++) {
          chain.push({ i, r: s.routers[i] });
          i = forwardOf(s.routers[i], i);
        }
        return stale + chain.map(({ i, r }) => cap(reason(r, i))).join(". ") + ".";
      }
      case "leaked": {
        // The network says who leaks: a router that passes routes from its providers or peers by policy.
        const leakers = inst.leakers || [];
        return leakers.length ? `${cap(routers(leakers))} pass${leakers.length > 1 ? "" : "es"} routes from a provider or peer on to another provider or peer, a leak by policy.` : "";
      }
      case "forward-valley": {
        // The first router on the packets' way that forwards on another route than the one it sent: told as it sends and as it forwards.
        const start = [...hitOf(t.mode)][0];
        if (start === undefined) return "";
        for (let prev = start, i = forwardOf(s.routers[start], start), k = 0; i >= 0 && i !== prev && k < s.routers.length; prev = i, i = forwardOf(s.routers[i], i), k++) {
          const r = s.routers[i], sent = ((r.out || []).find((o) => o.to === prev) || {}).path, to = forwardOf(r, i);
          if (sent && !same(sent.slice(1), r.best) && to >= 0 && to !== i) {
            const rel = relationOf(i, to);
            return `r${i} sends r${prev} ${route(sent.slice(1))} but forwards its packets on ${route(r.best)} to r${to}${rel ? `, its ${rel}` : ""}.`;
          }
        }
        return "";
      }
      case "inconsistent-export": {
        // Routers of one AS that send different paths, as the routers send them: their first path out, own AS dropped.
        const sent = (i) => ((s.routers[i].out || []).find((o) => o.path && asIndex(o.to) !== asIndex(i)) || {}).path;  // to another AS, so with its own AS first
        const who = [...hitOf(t.mode)].filter((i) => sent(i));
        const paths = who.map((i) => sent(i).slice(1));
        if (who.length < 2 || paths.every((p) => same(p, paths[0]))) return "";
        const why = PURE_OBGP.includes(t.mode) ? ": each offers the worst path it admitted" : "";
        return `${cap(who.map((i, k) => `r${i} sends ${route(paths[k])}`).join(", "))}, though one AS${why}.`;
      }
      case "no-convergence": {
        // Preferences that point round: set by policy, or by the relations, where a leak hands a provider its customer's route.
        const prefs = (inst.sessions || []).filter((x) => x.local_pref).map((x) => `r${x.to ?? 0} prefers routes from r${x.from ?? 0}`);
        const leaks = (inst.leakers || []).map((l) => [l, neighbors(l).filter((p) => relationOf(p, l) === "customer")]).filter(([, ps]) => ps.length)
          .map(([l, ps]) => `r${l} leaks routes to its provider${ps.length > 1 ? "s" : ""} ${ps.join(" and ")}, which prefer${ps.length > 1 ? "" : "s"} routes from customers`);
        const all = [...leaks, ...prefs];
        return all.length ? `${cap(all.join(", "))}, so each takes its neighbor's path, which then changes again.` : "";
      }
    }
    return "";
  }
  // The loop of a step under NS-BGP, from the first router of the loop whose own packets enter it, told hop by hop.
  function ingressLoop(s, loop) {
    for (const start of loop) {
      const seen = new Map(), hops = [];
      let at = start, came = null;
      for (let k = 0; k < 4 * n; k++) {
        const r = s.routers[at], key = `${at} ${came}`;
        if (seen.has(key)) {
          const round = hops.slice(seen.get(key));
          const told = round.map(([a, c, b]) => (c === null ? `r${a} sends its own packets to ${b}` : `r${a} sends packets from ${c} on to ${b}`));
          return `${cap(told.join(", "))}, and round again: under NS-BGP a router sends a packet on the route it offers the router the packet came from.`;
        }
        seen.set(key, hops.length);
        const h = came !== null && r.ingress ? r.ingress[came] : null;
        const to = h ? (asIndex(h.next_hop) === asIndex(at) ? -1 : h.next_hop) : came === null ? forwardOf(r, at) : -1;
        if (to < 0 || to === at) break;
        hops.push([at, came, to]);
        came = at;
        at = to;
      }
    }
    return "";
  }
  const own = (i) => [asNumber(asIndex(i)), ...((confedOf(i) && [confedOf(i).id]) || [])];
  const behind = (i, p) => { let k = 0; while (k < p.length && own(i).includes(p[k])) k++; return p.slice(k); };
  // Why a router withdraws its route from a neighbor although it had a route when it sent the withdrawal.
  function withdrawWhy(t, k) {
    const st = t.steps[k - 1];
    if (st.kind !== "withdraw" || !st.sent) return "";
    const r = t.steps[st.sent - 1].routers[st.from], o = (r.out || []).find((x) => x.to === st.to);
    if (r.best === null || !o || o.path) return "";
    if (o.not === "back to its source") return `its route comes from r${st.to} now`;
    if (o.not === "nothing to offer") {
      const none = nothingFor(t, st.sent, st.from, st.to);
      return none === "back to its source" ? `its route comes from r${st.to} now` : none;
    }
    return notWhy(st.from, st.to, o.not, full(r, r.exported) || r.best);
  }
  // A link's state: what each side offers the other now, and what the other does with it.
  // The rules of router i, from the network: its relations and what it filters, prefers and prepends.
  const relationOf = (i, j) => {
    if ((inst.customers || []).some(([p, c]) => p === i && c === j)) return "customer";
    if ((inst.customers || []).some(([p, c]) => p === j && c === i)) return "provider";
    if ((inst.peers || []).some(([a, b]) => (a === i && b === j) || (a === j && b === i))) return "peer";
    if ((inst.siblings || []).some(([a, b]) => (a === i && b === j) || (a === j && b === i))) return "sibling";
    return "";
  };
  function notWhy(i, j, not, path) {
    const x = (inst.sessions || []).find((y) => (y.from ?? 0) === i && (y.to ?? 0) === j) || {};
    if (not === "the export filter drops it" && x.deny_via) return `no path through ${asName(x.deny_via)}`;
    if (not === "the export filter drops it" && x.deny_export) return "it sends it nothing";
    if (not === "the relation forbids it" && relationOf(i, j)) return `a ${relationOf(i, j)} gets only customer routes`;
    if (not === "its AS is in the path") return confedOf(j) && (path || []).includes(confedOf(j).id) ? `the path runs through r${j}'s confederation ${confedOf(j).id}` : `the path runs through r${j}'s AS`;
    if (not === "the session is down") return "the link is down";
    if (not === "the export filter drops it") return "its export filter drops it";
    return esc(not);
  }

  const cap = (x) => (/^r\d/.test(x) ? x : x.charAt(0).toUpperCase() + x.slice(1));  // r1 stays as the map writes it

  const parts = {
    svg: root.querySelector("[data-map]"), timeline: root.querySelector("[data-timeline]"), counter: root.querySelector("[data-counter]"), phase: root.querySelector("[data-phase]"),
    prev: root.querySelector("[data-act=prev]"), play: root.querySelector("[data-act=play]"), next: root.querySelector("[data-act=next]"),
    loop: root.querySelector("[data-act=loop]"), speed: root.querySelector("[data-speed]"), speedLabel: root.querySelector("[data-speed-label]"),
  };
  async function load() {
    const sec = root.querySelector("[data-run]"), select = root.querySelector("[data-mode]");
    const mode = select.value;
    sec.querySelector("[data-state]").textContent = "";
    sec.querySelector("[data-wait]").hidden = false;
    const res = await fetch(`/simulation/${root.dataset.search}/${root.dataset.finding}/trace?mode=${encodeURIComponent(mode)}`);
    if (select.value !== mode) return;  // another mode was chosen meanwhile
    sec.querySelector("[data-wait]").hidden = true;
    if (!res.ok) { sec.querySelector("[data-state]").textContent = (await res.json().catch(() => ({}))).detail || "The simulator failed."; return; }
    const t = await res.json();
    if (affected.has(t.mode)) t.problem = analyse(t);
    const messages = t.steps.filter((x) => x.kind !== "event").length;
    // At rest, an order without end the simulator showed by a recurring state, or only no rest within the bound.
    const rest = (r) => r.converged ? "comes to rest" : r.cycle
      ? `back in its state of message ${r.cycle.from} at message ${r.cycle.from + r.cycle.length}, an order without end`
      : "no rest within the bound";
    // The verdict of this mode, said outright: the problem of the case, or none.
    const bad = affected.has(t.mode);
    sec.querySelector("[data-state]").innerHTML = `<span class="mr-1.5 rounded px-1.5 py-0.5 font-medium ${bad
      ? "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300" : "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"}">${bad ? "Problem" : "No problem"}</span>${t.cut ? `${t.cut} messages, the first ${messages} shown` : `${messages} messages`}, ${rest(t.result)}`;
    t.marks = marksOf(t);
    const map = window.SimMap.mount(parts, inst, t);
    // On a phone the map is wider than the screen: it opens at its middle, where the routers are, not at its margin.
    const box = parts.svg?.closest(".overflow-x-auto");
    if (box && box.scrollWidth > box.clientWidth) box.scrollLeft = (box.scrollWidth - box.clientWidth) / 2;
    // One sentence under the title: why it happens, else what happens. Its steps as the counter under the map counts
    // them: a message's step is where it arrives, "sent at" where it leaves.
    if (!t.problem) document.querySelector("[data-why]").textContent = `In ${t.mode} this network does not show the problem.`;
    else {
      const phase = (n, sent) => {
        const i = map.TL.findIndex((p) => p.k === n - 1 && p.ph === (sent ? "send" : "arrive"));
        return i >= 0 ? i : Math.max(0, map.TL.findIndex((p) => p.k === n - 1));
      };
      document.querySelector("[data-why]").textContent = (why(t) || t.problem.text)
        .replace(/\b(sent )?at step (\d+)/g, (_, sent, n) => `${sent || ""}in step ${phase(Number(n), !!sent)}`);
    }
  }
  // A menu whose mode has the problem is red, as are such modes in its list (ui.js carries both over).
  const mark = (select) => {
    const bad = select.selectedOptions[0]?.hasAttribute("data-problem");
    select.classList.toggle("text-rose-700", bad), select.classList.toggle("dark:text-rose-300", bad), select.classList.toggle("border-rose-400", bad);
  };
  const select = root.querySelector("[data-mode]");
  mark(select);
  select.onchange = () => { mark(select); load(); };
  load();

  // Below the map only what the map does not show: why the case lies outside the proofs, an aggregate or poisoning,
  // which the paths leave out, and what changes from outside. ASes, roles, relations and rules stand on the map.
  const facts = [];
  if (outside && root.dataset.proof === "outside its model") facts.push(["Proofs", `outside their model: ${outside}`]);
  if (originSet.length) facts.push(["Aggregate", `the origin announces an aggregate with the AS_SET {${originSet.join(", ")}}, one hop in every path, left out of the routes here`]);
  if (poison.length) facts.push(["Poison", `the origin names AS ${poison.join(", ")}`]);
  // An event the simulator holds back until the network is quiet carries a huge after.
  for (const e of inst.events || []) if (e.kind !== "expect") facts.push(["What happens", `${e.after >= 2 ** 29 ? "once the network is quiet" : `after ${e.after} messages`}, ${event(e)}`]);
  document.querySelector("[data-policies]").insertAdjacentHTML("beforeend", facts.map(([k, v], i) =>
    `<dt class="muted">${i && facts[i - 1][0] === k ? "" : k}</dt><dd>${cap(v)}</dd>`).join(""));
})();
