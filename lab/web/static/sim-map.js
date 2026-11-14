// The map of a simulator run: routers as cards, each link two belts, one per
// direction, routes as parcels on them, and what a router does as a speech
// bubble beside it. The run is told in phases: a message arrives and its
// router decides, then the messages that decision makes leave. Every phase
// has its bubble, so the map carries itself without a legend.
//
// SimMap.mount(parts, inst, trace) draws a run into the parts of the page:
// svg, timeline, prev, play, next, loop, speed, speedLabel, counter, phase.
(() => {
  const NS = "http://www.w3.org/2000/svg";
  const el = (tag, a, p) => { const e = document.createElementNS(NS, tag); for (const k in a) e.setAttribute(k, a[k]); if (p) p.appendChild(e); return e; };
  const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
  const r = (x) => `r${x}`;
  const mix = (c, f) => { const n = parseInt(c.slice(1), 16), m = (v) => Math.round(v + (255 - v) * f); return "#" + [n >> 16, (n >> 8) & 255, n & 255].map((v) => m(v).toString(16).padStart(2, "0")).join(""); };
  const tint = (c, a) => c + Math.round(a * 255).toString(16).padStart(2, "0");
  // A colour light enough to read on the dark bubble.
  const light = (c) => mix(c, 0.45);
  const kinds = { update: "update", withdraw: "withdrawal", refresh: "request to resend", "end-of-rib": "end of its table" };
  // What a router does with a route that arrives, from the trace's fate, and why the other route wins.
  const WINS = {
    "not stale": "the other is not stale", "reachable next hop": "the other's next hop is reachable",
    "higher local preference": "the other has a higher local preference", "own route": "it prefers its own route",
    "shorter AS path": "the other is shorter", "better origin": "the other has a better origin", "lower MED": "the other has a lower MED",
    "eBGP before iBGP": "the other comes over eBGP", older: "the other is older", "lower router ID": "the other has a lower router ID",
    "shorter cluster list": "the other has a shorter cluster list", "lower neighbor address": "the other comes from a lower address",
  };
  function decision(e) {
    switch (e.fate) {
      case "best": return "Forwards on it now.";
      case "admitted": return e.lost ? `Keeps it, but does not forward on it: ${WINS[e.lost] || e.lost}.` : "Keeps it, but does not forward on it.";
      case "set aside": return "Sets it aside: it is not better than its threshold.";
      case "loop": return "Drops it: its own AS is already on it.";
      case "filtered": return "Drops it: its import filter says no.";
      case "pruned": return "Drops it until the neighbor sends it again.";
      case "dropped": return "Drops it.";
      default: return `${e.fate}.`;
    }
  }
  // Why the route it forwards on wins, from the trace's reason why the other lost.
  const WINS_SELF = {
    "not stale": "it is not stale", "reachable next hop": "its next hop is reachable", "higher local preference": "it has a higher local preference",
    "own route": "it is its own route", "shorter AS path": "it is shorter", "better origin": "it has a better origin", "lower MED": "it has a lower MED",
    "eBGP before iBGP": "it comes over eBGP", older: "it is older", "lower router ID": "its sender has a lower router ID",
    "shorter cluster list": "it has a shorter cluster list", "lower neighbor address": "it comes from a lower address",
  };
  // Why a router sends a neighbor nothing, from the trace's out. "nothing to offer" goes without saying.
  const WHY_NOT = {
    "back to its source": (n) => `Not back to ${n}: it came from there.`,
    "its AS is in the path": (n) => `Not to ${n}: already on the path.`,
    "the relation forbids it": (n) => `Not to ${n}: the relation forbids it.`,
    "a community withholds it": (n) => `Not to ${n}: a community withholds it.`,
    "the export filter drops it": (n) => `Not to ${n}: its export filter drops it.`,
    "the session is down": (n) => `Not to ${n}: the link is down.`,
  };
  const names = (xs) => (xs.length > 1 ? `${xs.slice(0, -1).map(r).join(", ")} and ${r(xs[xs.length - 1])}` : r(xs[0]));
  // A text in lines: each sentence starts a line, its lines of even length, never a word alone on the last one.
  function wrap(text, n = 32) {
    const out = [];
    for (const sent of (text.match(/[^.:!?]+[.:!?]?/g) || [text]).map((t) => t.trim()).filter(Boolean)) {
      const words = sent.split(" "), lines = Math.ceil(sent.length / n), target = Math.ceil(sent.length / lines);
      const ls = [[]];
      for (const w of words) {
        const cur = ls[ls.length - 1], len = cur.join(" ").length;
        if (cur.length && len + 1 + w.length > target && ls.length < lines) ls.push([w]); else cur.push(w);
      }
      if (ls.length > 1 && ls[ls.length - 1].length === 1 && ls[ls.length - 2].length > 2) ls[ls.length - 1].unshift(ls[ls.length - 2].pop());
      out.push(...ls.map((l) => l.join(" ")));
    }
    return out;
  }

  let current = null;  // the map shown, for the keys
  document.addEventListener("keydown", (e) => {
    if (!current || e.target.closest?.("input, select, textarea")) return;
    if (e.key === "ArrowRight") { e.preventDefault(); current.stop(); current.step(1); }
    if (e.key === "ArrowLeft") { e.preventDefault(); current.stop(); current.step(-1); }
  });

  // The run and what the map says about it, without the page: positions in time, the routes of each router
  // and every text of the bubbles.
  function model(inst, T) {
    const steps = T.steps, N = inst.routers, ORIGIN = inst.origin ?? 0;
    // One table or a table per eBGP neighbor: the trace says so by the tables it carries.
    const PN = steps.some((s) => s.routers.some((x) => x.tables));
    const OBGP = T.mode.startsWith("obgp");
    // ---- AS numbers and routers ----
    const asIdx = (x) => (inst.as && inst.as.length ? inst.as[x] : x);
    const asn = (i) => (inst.asns && i < inst.asns.length ? inst.asns[i] : 65001 + i);
    const ASN = Array.from({ length: N }, (_, x) => asn(asIdx(x)));
    const routersOf = (a) => ASN.map((v, x) => (v === a ? x : -1)).filter((x) => x >= 0);
    const confeds = new Set((inst.confeds || []).map((c) => c.id));
    // An aggregate's AS_SET ends every path: the map leaves it out.
    const originSet = [...(inst.origin_set || [])].sort((a, b) => a - b);
    const bare = (p) => {
      const s = originSet.length;
      return s && p.length >= s && same([...p.slice(p.length - s)].sort((a, b) => a - b), originSet) ? p.slice(0, p.length - s) : p;
    };
    // Groups drawn as a frame behind their cards: an AS of several routers, a confederation. Each has a letter,
    // which stands in the paths for its AS, so that a path never names one of its routers for all of them.
    const groups = [];
    for (const a of [...new Set(ASN)]) if (routersOf(a).length > 1) groups.push({ kind: "AS", asn: a, members: routersOf(a) });
    for (const c of inst.confeds || []) groups.push({ kind: "confederation", asn: c.id, members: [...Array(N).keys()].filter((x) => c.members.includes(asIdx(x))) });
    groups.forEach((g, i) => { g.letter = String.fromCharCode(65 + i); });
    const groupOf = (a) => groups.find((g) => g.asn === a) || (a === 0 && groups.find((g) => g.kind === "confederation")) || null;
    // A route server passes routes on without its own AS: its own card shows them as its clients get them.
    const servers = new Set(inst.route_servers || []);
    // The full path from a router: its own AS, then the path it uses, as its neighbors get it over eBGP.
    const fullPath = (x, best) => (servers.has(x) ? bare(best) : [ASN[x], ...bare(best)]);
    // The rules on the session from a to b at step k: the instance's, changed by the events up to then.
    function policy(k, a, b) {
      const p = {};
      for (const v of inst.sessions || []) if ((v.from ?? 0) === a && (v.to ?? 0) === b) Object.assign(p, v);
      for (let j = 0; j <= k && j < steps.length; j++) {
        const e = steps[j].kind === "event" && steps[j].event;
        if (!e || (e.from ?? 0) !== a || (e.to ?? 0) !== b) continue;
        if (e.kind === "deny-export") p.deny_export = !!e.value;
        if (e.kind === "deny-import") p.deny_import = !!e.value;
        if (e.kind === "local-pref") p.local_pref = e.value || 0;
        if (e.kind === "prepend") p.prepend = e.value || 0;
      }
      return p;
    }

    // ---- Positions in time ----
    // Position -1 is the start, before the first message: the origin has the prefix, the others nothing yet.
    const START = { routers: Array.from({ length: N }, (_, x) => (x === ORIGIN
      ? { best: [], forward: x, exported: [], in: [], out: [], waits: false } : { best: null, forward: -1, in: [], out: [], waits: false })) };
    const R = (k, x) => (k < 0 ? START : steps[k]).routers[x];
    const isMsg = (s) => s.kind !== "event";
    const sentAfter = (i) => steps[i].sent - 1;  // sent: the 1-based step it was queued in, 0 at the start
    // What leaves after step k: the messages queued then.
    const createdAt = new Map();
    steps.forEach((s, i) => { if (isMsg(s)) { const k = s.sent - 1; if (!createdAt.has(k)) createdAt.set(k, []); createdAt.get(k).push(i); } });
    const created = (k) => createdAt.get(k) || [];
    // What x sends y now. iBGP and Add-Path may list several entries per neighbor: the first with a path counts.
    const offer = (k, x, y) => { const o = (R(k, x).out || []).find((e) => e.to === y && e.path); return o ? o.path : null; };
    // A path as the route behind its sender: without the sender's own AS or confederation in front and without the
    // aggregate's AS_SET at the end. What a router offers and what its message carries differ in these, not in the route.
    const confedOf = (x) => (inst.confeds || []).find((c) => c.members.includes(asIdx(x)));
    const behind = (x, p) => {
      if (!p) return null;
      const own = new Set([ASN[x], ...(confedOf(x) ? [confedOf(x).id, ...confedOf(x).members.map(asn)] : [])]);
      let k = 0; while (k < p.length && own.has(p[k])) k++;
      return bare(p.slice(k));
    };
    const sameRoute = (x, a, b) => same(behind(x, a), behind(x, b));
    // Whether x still offers y a route: a route server and Add-Path offer one neighbor several, any of them counts.
    const offers = (k, x, y, p) => {
      const o = (R(k, x).out || []).filter((e) => e.to === y && e.path);
      return p ? o.some((e) => sameRoute(x, e.path, p)) : !o.length;
    };
    // A message is no longer true once its sender would no longer send it, and was true when it was queued: only an
    // arrival or an event at the sender after that changes what it offers.
    const disagrees = (k, i) => !offers(k, steps[i].from, steps[i].to, steps[i].kind === "update" ? steps[i].path : null);
    const outdated = (k, i) => k >= 0 && k > sentAfter(i) && disagrees(k, i) && !(sentAfter(i) >= 0 && disagrees(sentAfter(i), i));
    // A route a router holds from a neighbor is stale once that neighbor no longer offers it.
    function stale(k, x, path) {
      if (k < 0 || !path || !path.length) return false;
      const e = (R(k, x).in || []).find((v) => same(v.path, path));
      return !!e && !offers(k, e.from, x, path);
    }
    // The loop the simulator found at this position, in the order packets go.
    function loopAt(k) {
      const l = k >= 0 ? steps[k].loop : null;
      if (!l || !l.length) return null;
      const set = new Set(l), order = [l[0]];
      while (order.length < l.length) { const f = R(k, order[order.length - 1]).forward; if (!set.has(f) || order.includes(f)) break; order.push(f); }
      return order.length === l.length ? order : l;
    }
    const K = steps.findIndex((_, k) => loopAt(k));
    // The routers that show the problem at step k: those of a loop, and those the page marks for the problem of the case.
    const problemAt = (k) => (k < 0 ? new Set() : new Set([...(loopAt(k) || []), ...((T.marks && T.marks[k]) || [])]));
    // Shown as no longer true only once its sender changed its mind. A route built on a lost one is still what its
    // sender offers: every route is doomed after a withdrawal, the map says so only once the sender knows.
    const untrue = (k, i) => outdated(k, i);

    // Every card keeps one height through the whole run, so nothing jumps from step to step.
    const cardH = new Map();
    for (let x = 0; x < N; x++) {
      let n = 0;
      for (let k = -1; k < steps.length; k++) n = Math.max(n, rowsOf(k, x).length);
      cardH.set(x, Math.max(100, 34 + n * 38 + 24));
    }
    const M = 82, LANE = 8;  // half the width of a card, half the gap between a link's belts
    // How far a line from a card's middle in direction (ux, uy) runs inside the card, with a small gap.
    const edge = (h, ux, uy) => Math.min(Math.abs(ux) > 1e-6 ? (M + 6) / Math.abs(ux) : Infinity, Math.abs(uy) > 1e-6 ? (h / 2 + 6) / Math.abs(uy) : Infinity);
    // The places: a diamond for four routers, else a circle, the first place on top, so wide that every belt
    // between two places shows at least BELT long beside the tallest card.
    const BELT = 90, tallest = Math.max(...cardH.values());
    const circle = (g) => Array.from({ length: N }, (_, i) => [320 + 220 * g * Math.sin((2 * Math.PI * i) / N), 215 - 160 * g * Math.cos((2 * Math.PI * i) / N)]);
    const roomy = (slots) => slots.every((a, i) => slots.every((b, j) => {
      if (j <= i) return true;
      const L = Math.hypot(b[0] - a[0], b[1] - a[1]), ux = (b[0] - a[0]) / L, uy = (b[1] - a[1]) / L;
      return L - 2 * edge(tallest, ux, uy) >= BELT;
    }));
    let SLOTS = N === 4 ? [[320, 85], [620, 240], [320, 395], [20, 240]] : circle(1);
    for (let g = 1; !roomy(SLOTS) && g < 4; g += 0.1) SLOTS = N === 4 ? [[320, 85 - 80 * (g - 1)], [320 + 300 * g, 240], [320, 395 + 80 * (g - 1)], [320 - 300 * g, 240]] : circle(g);
    // The origin on top, the others in the order whose links cross least, the first such order in router order.
    const POS = (() => {
      const cross = (p, q, r, t) => {
        const o = (a, b, c) => Math.sign((b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0]));
        return o(p, q, r) * o(p, q, t) < 0 && o(r, t, p) * o(r, t, q) < 0;
      };
      const crossings = (pos) => {
        let c = 0;
        for (let i = 0; i < inst.links.length; i++) for (let j = i + 1; j < inst.links.length; j++) {
          const [a, b] = inst.links[i], [d, e] = inst.links[j];
          if (a !== d && a !== e && b !== d && b !== e && cross(pos[a], pos[b], pos[d], pos[e])) c++;
        }
        return c;
      };
      // A frame holds its members only: a card of another router touching it costs as much as many crossings.
      // Cards are compared whole, some 100 high before their tables are known, the frame as drawn below.
      const intruders = (pos) => groups.reduce((t, g) => {
        const xs = g.members.map((x) => pos[x][0]), ys = g.members.map((x) => pos[x][1]);
        const [x0, x1, y0, y1] = [Math.min(...xs) - M - 14, Math.max(...xs) + M + 14, Math.min(...ys) - 80, Math.max(...ys) + 64];
        return t + [...Array(N).keys()].filter((y) => !g.members.includes(y) && pos[y][0] + M > x0 && pos[y][0] - M < x1 && pos[y][1] + 50 > y0 && pos[y][1] - 50 < y1).length;
      }, 0);
      const others = [...Array(N).keys()].filter((x) => x !== ORIGIN);
      let best = null, fewest = Infinity;
      const place = (order) => { const pos = []; pos[ORIGIN] = SLOTS[0]; order.forEach((x, i) => { pos[x] = SLOTS[i + 1]; }); return pos; };
      const permute = (rest, order) => {
        if (fewest === 0) return;
        if (!rest.length) { const pos = place(order), c = crossings(pos) + 10 * intruders(pos); if (c < fewest) { fewest = c; best = pos; } return; }
        rest.forEach((x, i) => permute([...rest.slice(0, i), ...rest.slice(i + 1)], [...order, x]));
      };
      if (N <= 8) permute(others, []); else best = place(others);
      return best;
    })();
    function rowsOf(k, x) {
      const rt = R(k, x), rows = [];
      if (x === ORIGIN) return rows;
      if (!rt.best) {
        // Without a route: whether it waits, and what it set aside, which a refresh may bring back.
        if (rt.waits) rows.push({ p: null, op: 1, waits: true, text: "waits for a refresh" });
        for (const p of (rt.set_aside || []).filter((q) => q && q.length)) rows.push({ p, op: 1, aside: true, text: "set aside" });
        for (const v of (rt.in || []).filter((q) => q.fate === "pruned" && q.path)) rows.push({ p: v.path, from: v.from, op: 1, pruned: true, text: "pruned" });
        return rows;
      }
      {
        const thr = OBGP && !PN && rt.exported && rt.exported.length ? rt.exported : null;
        const isThr = (p) => thr && same(p, thr);
        rows.push({ p: rt.best, from: ((rt.in || []).find((v) => v.fate === "best") || {}).from, op: 1, text: isThr(rt.best) ? "forwards on, threshold" : "forwards on" });
        for (const p of (rt.admitted || []).filter((q) => q && q.length && !same(q, rt.best)))
          rows.push({ p, op: 1, text: isThr(p) ? "threshold" : "kept" });
        for (const p of (rt.set_aside || []).filter((q) => q && q.length)) rows.push({ p, op: 1, aside: true, text: "set aside" });
        for (const v of (rt.in || []).filter((q) => q.fate === "pruned" && q.path)) rows.push({ p: v.path, from: v.from, op: 1, pruned: true, text: "pruned" });
        // Forwarding by where a packet came from (NS-BGP, -pn): packets of a neighbor that go elsewhere than its own.
        for (const [j, h] of elsewhere(k, x)) rows.push({ p: null, op: 1, ingress: true, text: `from ${r(+j)}, on to ${r(h)}` });
      }
      return rows;
    }
    // The neighbors whose packets x forwards elsewhere than its own, each with where: only those it offers a route,
    // since only they send it packets.
    function elsewhere(k, x) {
      return Object.entries(R(k, x).ingress || {})
        .filter(([j, h]) => h.next_hop >= 0 && h.next_hop !== R(k, x).forward && offer(k, x, +j)).map(([j, h]) => [j, h.next_hop]);
    }
    function geo(a, b, lane) {
      const [ax, ay] = POS[a], [bx, by] = POS[b], L = Math.hypot(bx - ax, by - ay), ux = (bx - ax) / L, uy = (by - ay) / L, nx = -uy, ny = ux;
      const ta = edge(cardH.get(a), ux, uy), tb = edge(cardH.get(b), ux, uy);
      return { x0: ax + ux * ta + nx * lane, y0: ay + uy * ta + ny * lane, x1: bx - ux * tb + nx * lane, y1: by - uy * tb + ny * lane, ux, uy, nx, ny };
    }
    const at = (g, t) => [g.x0 + (g.x1 - g.x0) * t, g.y0 + (g.y1 - g.y0) * t];
    // Where a router's packets go: its own, and with NS-BGP those it passes on for a neighbor that offers it a route.
    const own = (k, p, q) => R(k, p).forward === q;
    const passed = (k, p, q) => Object.entries(R(k, p).ingress || {}).some(([j, h]) => h.next_hop === q && offer(k, p, +j));
    const sends = (k, p, q) => own(k, p, q) || passed(k, p, q);
    const down = (k, p, q) => (R(k, p).out || []).some((o) => o.to === q && o.not === "the session is down");

    // ---- What a router does, in plain words ----
    // OBGP's threshold with one table: the worst admitted path, which it also offers.
    const threshold = (k, x) => (OBGP && !PN && R(k, x).best && R(k, x).exported && R(k, x).exported.length ? R(k, x).exported : null);
    const outsOf = (k, x) => JSON.stringify((R(k, x).out || []).map((o) => o.path || null));
    // The relation of x to y, as y is to x: "customer", "provider", "peer", "sibling" or "".
    const relation = (x, y) => {
      if ((inst.customers || []).some(([p, c]) => p === x && c === y)) return "customer";
      if ((inst.customers || []).some(([p, c]) => p === y && c === x)) return "provider";
      if ((inst.peers || []).some(([a, b]) => (a === x && b === y) || (a === y && b === x))) return "peer";
      if ((inst.siblings || []).some(([a, b]) => (a === x && b === y) || (a === y && b === x))) return "sibling";
      return "";
    };
    const asName = (a) => { const rs = routersOf(a); return rs.length === 1 ? r(rs[0]) : `AS ${a}`; };
    // Why x sends its neighbors nothing, the same reason to several on one line. Relations and filters said in full.
    function whyNot(k, x) {
      const by = new Map(), rt = R(k, x), src = ((rt.in || []).find((v) => v.fate === "best") || {}).from;
      const reason = (o) => {
        if (o.not === "the relation forbids it" && src !== undefined && relation(x, src))
          return (n) => `Not to ${n}: a route from its ${relation(x, src)} goes only to its customers.`;
        if (o.not === "the export filter drops it") {
          const f = (inst.sessions || []).find((v) => (v.from ?? 0) === x && (v.to ?? 0) === o.to && v.deny_via);
          if (f) return (n) => `Not to ${n}: it sends no path through ${asName(f.deny_via)} there.`;
        }
        return WHY_NOT[o.not];
      };
      for (const o of rt.out || []) {
        if (o.path || !o.not || !WHY_NOT[o.not]) continue;
        const f = reason(o), key = f(" ");
        if (!by.has(key)) by.set(key, [f, []]);
        by.get(key)[1].push(o.to);
      }
      return [...by.values()].map(([f, to]) => f(names(to)));
    }
    function arrivalText(k) {
      const s = steps[k], x = s.to, rt = R(k, x), was = R(k - 1, x);
      const e = (rt.in || []).find((v) => v.from === s.from && same(v.path, s.path)) || (rt.in || []).find((v) => v.from === s.from);
      const out = [];
      if (s.kind === "update" && e) {
        if (untrue(k - 1, k)) out.push("This route is stale: its sender no longer sends it.");
        // Why it wins: the reason the route it forwarded on before now loses.
        const prev = (was.in || []).find((v) => v.fate === "best" && v.from !== s.from), now = prev && (rt.in || []).find((v) => v.from === prev.from);
        out.push(e.fate === "best" && now && now.lost && WINS_SELF[now.lost] ? `Forwards on it now: ${WINS_SELF[now.lost]}.` : decision(e));
        if (e.fate === "best" && now && now.fate !== "best") out.push(now.fate === "admitted" ? `Keeps r${prev.from}'s route as well.` : now.fate === "set aside" ? `Sets r${prev.from}'s route aside.` : `Drops r${prev.from}'s route.`);
      } else if (s.kind === "refresh") out.push(`Sends r${s.from} its routes again.`);
      else if (s.kind === "end-of-rib") out.push(`Has all routes of r${s.from} now.`);
      else if (!rt.best && was.best) out.push("Loses its route. It has nothing to forward on.");
      else if (rt.best && !same(was.best, rt.best)) {
        const b = (rt.in || []).find((v) => v.fate === "best");
        out.push(b ? `Switches to the route of ${r(b.from)}.` : "Switches to another route.");
      }
      else if ((was.admitted || []).length > (rt.admitted || []).length) out.push(`Keeps forwarding on its route. Drops r${s.from}'s route.`);
      // Where packets of a neighbor go, when that changes with forwarding by where they came from.
      for (const [j, h] of Object.entries(rt.ingress || {})) {
        const before = ((was.ingress || {})[j] || {}).next_hop;
        if (h.next_hop >= 0 && before !== undefined && before !== h.next_hop && offer(k, x, +j)) out.push(`Packets from ${r(+j)} now go on to ${r(h.next_hop)}.`);
      }
      // Routes pruned now: OBGP's hard pruning drops them with a withdrawal through the same ASes.
      for (const v of (rt.in || []).filter((q) => q.fate === "pruned" && q.from !== s.from))
        if (((was.in || []).find((q) => q.from === v.from) || {}).fate !== "pruned")
          out.push(`Drops ${r(v.from)}'s route too: a withdrawal through the same ASes prunes it until ${r(v.from)} sends it again.`);
      // A route it held without forwarding on it, gone with its sender's withdrawal.
      const held = (was.in || []).find((v) => v.from === s.from && v.path), still = (rt.in || []).find((v) => v.from === s.from && v.path);
      if (!out.length && held && !still) out.push(held.fate === "pruned" ? `Drops r${s.from}'s pruned route.` : `Drops r${s.from}'s route.`);
      if (!out.length && was.waits && !rt.waits) out.push(rt.best ? "Stops waiting for a refresh." : "Stops waiting for a refresh. It has no route now.");
      if (!out.length && !was.waits && rt.waits) out.push("Has no route it may use now. Waits for a neighbor to send its routes again.");
      if (!out.length && (rt.set_aside || []).length < (was.set_aside || []).length) out.push("Drops a route it had set aside.");
      // A change of the threshold is a change, even when the route it forwards on stays.
      const t0 = threshold(k - 1, x), t1 = threshold(k, x), moved = OBGP && !PN && !same(t0, t1) && rt.best;
      if (!out.length && !moved) out.push("Nothing changes for it.");
      const items = out.length ? [out.join(" ")] : [];
      if (moved) { if (t1) items.push("Its threshold is now:", { chips: fullPath(x, t1) }); else items.push("It has no threshold now."); }
      // Something changed but nothing leaves: why not, or that its offer stays the same.
      const changed = !(out.length === 1 && out[0] === "Nothing changes for it.");
      // A run cut short or without rest ends with messages it queued but did not play: "sends nothing" may be false there.
      const playedAll = (T.result || {}).converged && !T.cut;
      if (changed && (rt.best || was.best) && !created(k).some((i) => steps[i].from === x) && (playedAll || outsOf(k - 1, x) === outsOf(k, x))) {
        const why = whyNot(k, x);
        if (outsOf(k - 1, x) === outsOf(k, x) && rt.best && was.best) items.push("Its offer stays the same, so it sends nothing new.");
        else if (why.length) items.push("Sends nothing.", ...why);
      }
      return items;
    }
    // A change from outside, said at the router it happens to: [router, text].
    function eventItems(ev) {
      if (!ev) return [ORIGIN, "Something changes from outside."];
      const f = ev.from ?? ORIGIN, t = ev.to ?? 0, v = ev.value || 0;
      const E = {
        withdraw: [f, "Withdraws its prefix. It has no route now."],
        announce: [f, "Announces its prefix again."],
        originate: [f, "Starts to originate the prefix too."],
        down: [f, v === 2 ? `r${t} drops its packets without notice. The link counts as down.` : v === 1 ? `Its link to r${t} is cut. Both ends keep the routes as stale for now.` : `Its link to r${t} goes down.`],
        up: [f, `Its link to r${t} comes back. They exchange their routes.`],
        restart: [f, v === 1 ? "Restarts gracefully. Its peers keep its routes for now." : "Restarts and forgets all its routes."],
        expire: [f, `The restart time of its link to r${t} ends. The stale routes go.`],
        prepend: [f, `Adds its AS ${v} more times on routes to r${t}.`],
        "prepend-all": [f, `Adds its AS ${v} more times on routes to other ASes.`],
        "local-pref": [t, v ? `Sets local preference ${v} on routes from r${f}.` : `Sets local preference back to the default on routes from r${f}.`],
        expect: [f, "The lab checks the routes here. Nothing changes."],
        igp: [f, v ? `Its link to r${t} inside the AS gets cost ${v}.` : `Its link to r${t} inside the AS goes away.`],
        "deny-export": [f, v ? `Stops sending routes to r${t}.` : `Sends routes to r${t} again.`],
        "deny-import": [t, v ? `Stops taking routes from r${f}.` : `Takes routes from r${f} again.`],
      }[ev.kind] || [f, `Change from outside: ${ev.kind}.`];
      return E;
    }
    // What leaves a router after a step: one line per kind of message, the same route to several neighbors on one line.
    // [router, items] for every router that sends after step k.
    function sendItems(k) {
      return [...new Set(created(k).map((i) => steps[i].from))].map((x) => {
        const groups = new Map();
        for (const i of created(k).filter((i) => steps[i].from === x)) {
          const s = steps[i], key = s.kind + JSON.stringify(s.path || null);
          if (!groups.has(key)) groups.set(key, { kind: s.kind, path: s.path, to: [] });
          groups.get(key).to.push(s.to);
        }
        const rows = [];
        for (const gr of groups.values()) {
          if (gr.kind === "update") {
            rows.push(`Sends ${names(gr.to)} its route:`, { chips: bare(gr.path) });
            // A leak: a route from a provider or peer passed on to another provider or peer.
            const src = ((R(k, x).in || []).find((v) => v.fate === "best") || {}).from;
            const up = (y) => ["provider", "peer"].includes(relation(x, y));
            const leaked = src !== undefined && up(src) ? gr.to.filter(up) : [];
            if (leaked.length && (inst.leakers || []).includes(x)) rows.push(`That is a leak: ${names(leaked)} ${leaked.length > 1 ? "are" : "is"} its ${relation(x, leaked[0])}, and so is ${r(src)}, where the route comes from.`);
          }
          else if (gr.kind === "withdraw") rows.push(`Withdraws from ${names(gr.to)}.`);
          else rows.push(`Sends ${names(gr.to)} a ${kinds[gr.kind] || gr.kind}.`);
        }
        rows.push(...whyNot(k, x));
        return [x, rows];
      });
    }

    // ---- The timeline: each step in two phases, "arrive" (a message reaches its router, which decides) and
    // "send" (the messages that decision makes leave). A step that makes none has no "send" phase. ----
    const TL = [];
    for (let k = -1; k < steps.length; k++) { TL.push({ k, ph: "arrive" }); if (created(k).length) TL.push({ k, ph: "send" }); }
    // What kind of step a position of the timeline is, in a few words beside the counter.
    function phaseText(i) {
      const { k, ph } = TL[i];
      if (ph === "send") { const xs = [...new Set(created(k).map((j) => steps[j].from))]; return `${names(xs)} send${xs.length > 1 ? "" : "s"}`; }
      if (k < 0) return "Start";
      const s = steps[k];
      if (!isMsg(s)) {
        const [x, text] = eventItems(s.event), first = (text.match(/^[^.:]+/) || [text])[0];
        return `From outside at ${r(x)}: ${first.charAt(0).toLowerCase()}${first.slice(1)}`;
      }
      return `${r(s.from)}'s ${kinds[s.kind] || "message"} arrives at ${r(s.to)}`;
    }
    return { steps, N, ORIGIN, PN, OBGP, ASN, asIdx, routersOf, confeds, bare, fullPath, groups, groupOf, servers, policy, relation, asName, R, isMsg, sentAfter, created, offer, stale, loopAt, K, untrue,
      M, LANE, POS, rowsOf, cardH, geo, at, own, passed, sends, down, threshold, whyNot, arrivalText, eventItems, sendItems, TL, phaseText, problemAt };
  }

  function mount(parts, inst, T) {
    if (current) current.destroy();
    const svg = parts.svg, m = model(inst, T);
    const {
      steps, N, ORIGIN, PN, OBGP, ASN, routersOf, bare, fullPath, groups, groupOf, policy, relation, asName, R, isMsg, sentAfter, created,
      offer, stale, loopAt, K, untrue, M, LANE, POS, rowsOf, cardH, geo, at, own, passed, sends, down, arrivalText, eventItems, sendItems,
      TL, phaseText, problemAt
    } = m;
    const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
    // Router colours, --router-1 to --router-8 in styles.css: none of the lab's meanings (U of T blue a route,
    // teal a role, violet waits, rose the problem), lighter in dark mode.
    let HUES = [];
    const hue = (x) => HUES[x % HUES.length];
    let C = {};
    const colours = () => {
      HUES = Array.from({ length: 8 }, (_, i) => css(`--router-${i + 1}`));
      C = { card: css("--graph-bg"), tip: css("--graph-tip"), belt: css("--graph-none"), muted: css("--graph-node"), faint: css("--graph-none-line"),
        rose: css("--graph-problem"), roseSoft: css("--graph-problem-soft"), violet: css("--graph-waits"), role: css("--graph-role"), group: css("--graph-node"), frame: css("--graph-as-1") };
    };
    colours();

    // A chip in a path: the router of that AS, the AS when it holds several routers, the confederation, or "ext".
    // A chip in a path: the router of that AS, the letter of its frame for an AS of several routers or a confederation,
    // "ext" for an AS outside the network. {rs: x}: the route server it passed, an outline that is no hop.
    function chipOf(a) {
      if (a && a.rs !== undefined) return { text: r(a.rs), color: C.role, outline: true };
      const rs = routersOf(a);
      if (rs.length === 1) return { text: r(rs[0]), color: hue(rs[0]) };
      const g = groupOf(a);
      if (g) return { text: g.letter, color: C.group };
      return { text: "ext", color: C.faint };
    }
    // A route as its chips on a card: after the router itself, the route server it came through, if any. A row that
    // knows its neighbor asks that neighbor only: the same path may come straight from another one.
    const chipsOf = (x, p, from) => {
      const v = (R(curK, x).in || []).find((q) => q.over === "rs" && q.path && same(q.path, p) && (from === undefined || q.from === from));
      const full = fullPath(x, p);
      return v ? [full[0], { rs: v.from }, ...full.slice(1)] : full;
    };
    let curK = -1;
    // ---- The map ----
    // A frame behind the cards of a group, with room above them for its name.
    const frames = groups.map((g) => {
      const x0 = Math.min(...g.members.map((x) => POS[x][0])) - M - 14, x1 = Math.max(...g.members.map((x) => POS[x][0])) + M + 14;
      const y0 = Math.min(...g.members.map((x) => POS[x][1] - cardH.get(x) / 2)) - 30, y1 = Math.max(...g.members.map((x) => POS[x][1] + cardH.get(x) / 2)) + 14;
      return { g, x0, x1, y0, y1 };
    });
    // Room for the bubbles around the routers.
    {
      const xs = [...POS.map((p) => p[0] - M), ...POS.map((p) => p[0] + M), ...frames.flatMap((f) => [f.x0, f.x1])];
      const ys = [...POS.map((p, x) => [p[1] - cardH.get(x) / 2, p[1] + cardH.get(x) / 2]).flat(), ...frames.flatMap((f) => [f.y0, f.y1])];
      const x0 = Math.min(...xs) - 230, x1 = Math.max(...xs) + 230, y0 = Math.min(...ys) - 110, y1 = Math.max(...ys) + 110;
      svg.setAttribute("viewBox", `${x0} ${y0} ${x1 - x0} ${y1 - y0}`);
    }
    function chipRow(g, path, cx, y, width) {
      const cw = Math.min(30, (width - 4) / path.length), x0 = cx - (path.length * cw) / 2;
      path.forEach((a, j) => {
        const c = chipOf(a);
        el("rect", { x: x0 + j * cw + (c.outline ? 1 : 0), y: y + (c.outline ? 1 : 0), width: cw - 2 - (c.outline ? 2 : 0), height: c.outline ? 18 : 20, rx: 4,
          fill: c.outline ? C.card : c.color, stroke: c.outline ? c.color : "none", "stroke-width": 1.5 }, g);
        el("text", { x: x0 + j * cw + (cw - 2) / 2, y: y + 14.5, "text-anchor": "middle", "font-size": cw < 23 ? 12.5 : 13.5, "font-weight": 700, fill: c.outline ? c.color : "#fff" }, g).textContent = c.text;
      });
    }

    let chosen = ORIGIN;  // the router whose tables per neighbor show at its lanes
    function render(k, opts = {}) {
      svg.innerHTML = "";
      el("defs", {}, svg).innerHTML = `<filter id="sim-sh" x="-20%" y="-20%" width="140%" height="160%"><feDropShadow dx="0" dy="1" stdDeviation="1.2" flood-color="#0f172a" flood-opacity=".12"/></filter>
        <pattern id="sim-hatch" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="4" height="4" fill="${C.roseSoft}"/><line x1="0" y1="0" x2="0" y2="4" stroke="${C.rose}" stroke-width="1.5"/></pattern>
        <style>.fadein { animation: fin .6s ease-out; } @keyframes fin { from { opacity: 0; } }
          .pulse { animation: pulse .7s ease-out forwards; transform-box: fill-box; transform-origin: center; }
          @keyframes pulse { from { opacity: .55; transform: scale(1); } to { opacity: 0; transform: scale(1.45); } }
          .run { animation: run 0.7s linear infinite; } @keyframes run { to { stroke-dashoffset: -14; } }
          .pass { animation: pass 0.7s linear infinite; } @keyframes pass { to { stroke-dashoffset: -8; } }
          @media (prefers-reduced-motion: reduce) { .fadein, .pulse, .run, .pass { animation: none; } }</style>`;
      curK = k;
      const loop = loopAt(k), inC = new Set(loop || []), hot = problemAt(k);
      // Frames: an AS of several routers shaded, a confederation shaded with a dashed border, each named with its letter.
      const frameNames = [];  // drawn over the belts
      for (const f of frames) {
        const confed = f.g.kind === "confederation";
        el("rect", { x: f.x0, y: f.y0, width: f.x1 - f.x0, height: f.y1 - f.y0, rx: 16, fill: C.frame, stroke: confed ? C.group : "none", "stroke-width": 1.2, ...(confed ? { "stroke-dasharray": "5 4" } : {}) }, svg);
        frameNames.push([f, `${f.g.letter}: ${confed ? "confederation" : "AS"} ${f.g.asn}`]);
      }
      const lanes = [];
      for (const [a, b] of inst.links) for (const [p, q] of [[a, b], [b, a]]) lanes.push([p, q]);
      // The loop, named once beside it.
      for (const [p, q] of lanes) if (inC.has(p) && inC.has(q) && sends(k, p, q)) {
        const g = geo(p, q, LANE), [mx, my] = at(geo(p, q, 0), 0.5);
        const onCard = (px, py) => [...cardH].some(([y, hh]) => Math.abs(px - POS[y][0]) < M + 50 && Math.abs(py - POS[y][1]) < hh / 2 + 12);
        const d = [48, -48, 70, -70].find((v) => !onCard(mx - g.nx * v, my - g.ny * v)) ?? 48;
        el("text", { x: mx - g.nx * d, y: my - g.ny * d + 5, "text-anchor": "middle", "font-size": 13.5, "font-weight": 600, fill: C.rose, stroke: C.card, "stroke-width": 4, "paint-order": "stroke" }, svg).textContent = "packets circle";
        break;
      }
      // Belts: grey and still, or running in the colour of the router whose packets go on them, finer and paler where it
      // only passes on packets of a neighbor (a table per neighbor). A link that is down: cut.
      for (const [p, q] of lanes) {
        if (down(k, p, q)) {
          const g = geo(p, q, LANE), [cx, cy] = at(geo(p, q, 0), 0.5);
          el("line", { x1: g.x0, y1: g.y0, x2: g.x1, y2: g.y1, stroke: C.belt, "stroke-width": 4, "stroke-dasharray": "6 6" }, svg);
          if (p < q) el("text", { x: cx, y: cy + 6, "text-anchor": "middle", "font-size": 18, "font-weight": 700, fill: C.rose, stroke: C.card, "stroke-width": 4, "paint-order": "stroke" }, svg).textContent = "×";
          continue;
        }
        const g = geo(p, q, LANE), mine = own(k, p, q), live = mine || passed(k, p, q), c = live && inC.has(p) && inC.has(q) ? C.rose : hue(p);
        const lg = el("g", { class: opts.pulse !== undefined && live && !sends(k - 1, p, q) ? "fadein" : "" }, svg);
        el("line", { x1: g.x0, y1: g.y0, x2: g.x1, y2: g.y1, stroke: live ? tint(c, 0.22) : C.belt, "stroke-width": live ? 10 : 6, "stroke-linecap": "round" }, lg);
        if (live) {
          el("line", { x1: g.x0, y1: g.y0, x2: g.x1, y2: g.y1, stroke: c, "stroke-width": 10, "stroke-dasharray": mine ? "4 10" : "2 6", class: mine ? "run" : "pass", opacity: mine ? 1 : 0.6 }, lg);
        }
      }
      for (const [f, text] of frameNames)
        el("text", { x: f.x0 + 12, y: f.y0 + 19, "font-size": 13, "font-weight": 600, fill: C.group, stroke: C.card, "stroke-width": 4, "paint-order": "stroke" }, svg).textContent = text;
      // The rules of each session as small tags on its belt: what the sender does at its end, what the receiver does at
      // its end, and the relation of the two at the middle of the link.
      const tag = (g, t, text) => {
        const w = text.length * 7.1 + 14, len = Math.hypot(g.x1 - g.x0, g.y1 - g.y0);
        // Its end nearest the card clear of it: how far the tag reaches along the belt, from its middle.
        if (len > 0 && t !== 0) {
          const reach = (Math.abs(g.x1 - g.x0) * w / 2 + Math.abs(g.y1 - g.y0) * 10) / len + 6;
          t = t < 0.5 ? Math.min(0.45, Math.max(t, reach / len)) : Math.max(0.55, Math.min(t, 1 - reach / len));
        }
        // Beside its belt, away from the other direction's, so that the parcels pass under it, not through it.
        const [bx, by] = at(g, t), off = t === 0 ? 0 : 18, tx = bx + g.nx * off, ty = by + g.ny * off, tg = el("g", { "data-label": "rule" }, svg);
        el("rect", { x: tx - w / 2, y: ty - 10, width: w, height: 20, rx: 10, fill: C.card, stroke: C.role, "stroke-width": 1.2 }, tg);
        el("text", { x: tx, y: ty + 4.5, "text-anchor": "middle", "font-size": 13, "font-weight": 600, fill: C.role }, tg).textContent = text;
      };
      for (const [p, q] of lanes) {
        const v = policy(k, p, q), g = geo(p, q, LANE), withheld = /^0:(\d+)$/.exec(v.tag || "");
        const sender = [v.deny_export && "sends nothing", v.deny_via && `no path via ${asName(v.deny_via)}`, v.prepend && `prepends ${v.prepend}×`,
          v.med && `MED ${v.med}`, v.partial_transit && "customers' routes only"].filter(Boolean);
        const receiver = [v.deny_import && "takes nothing", v.local_pref && `pref ${v.local_pref}`, v.tag && (withheld ? `tags: not to ${asName(+withheld[1])}` : `tags ${v.tag}`)].filter(Boolean);
        if (sender.length) tag(g, 0.22, sender.join(", "));
        if (receiver.length) tag(g, 0.78, receiver.join(", "));
      }
      for (const [a, b] of inst.links) {
        const rel = relation(a, b), mid = at(geo(a, b, 0), 0.5), g = geo(a, b, 0);
        if (!rel) continue;
        // Provider to customer: named at the customer's end. Peers and siblings: at the middle.
        const text = rel === "customer" ? `${r(b)} customer of ${r(a)}` : rel === "provider" ? `${r(a)} customer of ${r(b)}` : rel === "peer" ? "peers" : "siblings";
        tag({ ...g, x0: mid[0], y0: mid[1], x1: mid[0], y1: mid[1] }, 0, text);
      }
      // Messages on their way, all moving on together by their share of the way done, a later one behind.
      const q = new Map(), kf = opts.kf ?? k;
      steps.forEach((s, i) => {
        if (!isMsg(s) || i <= k || s.sent > k + 1 || (opts.hideNew && s.sent === k + 1)) return;
        const a = sentAfter(i), key = s.from + "-" + s.to;
        const share = Math.min(1, Math.max(0, (kf - a) / (i - a)));
        // The message that arrives now runs on into its router's card, which takes it in, drawn over it.
        const len = Math.hypot(...(() => { const g0 = geo(s.from, s.to, LANE); return [g0.x1 - g0.x0, g0.y1 - g0.y0]; })());
        let t = i === opts.eat ? 0.06 + (0.94 + 40 / len) * share : 0.06 + 0.9 * share;
        if (q.has(key) && i !== opts.eat) t = Math.min(t, q.get(key) - 0.13);
        t = Math.max(0.03, t); q.set(key, t);
        const g = geo(s.from, s.to, LANE), [px, py] = at(g, t), c = hue(s.from);
        const old = untrue(k, i), upd = s.kind === "update", ask = s.kind === "refresh";
        const pg = el("g", { style: "cursor:pointer" }, svg);
        el("rect", { x: px - 8, y: py - 6.5, width: 16, height: 13, rx: 3, fill: old ? "url(#sim-hatch)" : upd ? tint(c, 0.25) : C.card,
          stroke: old ? C.rose : ask ? C.violet : c, "stroke-width": 1.6, ...(upd || old ? {} : { "stroke-dasharray": "2.5 2" }) }, pg);
        if (ask) el("text", { x: px, y: py + 3.5, "text-anchor": "middle", "font-size": 13.5, "font-weight": 800, fill: C.violet }, pg).textContent = "?";
        // Its label, the path as chips: for the message of the loop, one no longer true, or on tap and hover.
        const show = (i === K || old) && t > 0.04 && t < 1;
        const [ax, ay] = at(g, Math.max(t, 0.35)), lab = el("g", { opacity: show ? 1 : 0, ...(show ? { "data-label": i } : {}) }, svg), lx = ax + g.nx * 42, ly = ay + g.ny * 42;  // beyond the rule tags beside the belt
        if (upd) chipRow(lab, bare(s.path), lx, ly - 10, s.path.length * 30 + 4);
        else el("text", { x: lx, y: ly + 4, "text-anchor": "middle", "font-size": 13.5, fill: ask ? C.violet : C.muted, stroke: C.card, "stroke-width": 4, "paint-order": "stroke" }, lab).textContent = kinds[s.kind] || s.kind;
        let pinned = show;
        pg.addEventListener("mouseenter", () => lab.setAttribute("opacity", 1));
        pg.addEventListener("mouseleave", () => lab.setAttribute("opacity", pinned ? 1 : 0));
        pg.addEventListener("click", () => { pinned = !pinned; lab.setAttribute("opacity", pinned ? 1 : 0); });
      });
      // Routers: a card with a border in its colour, dashed without a route, rose in the loop. Inside, its table,
      // each route as the full path from the router. With OBGP the worst kept one is the threshold a new route must beat.
      for (let x = 0; x < N; x++) {
        const [cx, cy] = POS[x], rt = R(k, x), on = !!rt.best, c = hue(x), g = el("g", { "data-router": x }, svg);
        const sent = (rt.out || []).filter((o) => o.path), rows = rowsOf(k, x), H = cardH.get(x), top = cy - H / 2;
        if (x === opts.pulse) el("rect", { x: cx - M, y: top, width: 2 * M, height: H, rx: 11, fill: "none", stroke: c, "stroke-width": 6, class: "pulse" }, svg);
        el("rect", { x: cx - M, y: top, width: 2 * M, height: H, rx: 12, fill: C.card, stroke: hot.has(x) ? C.rose : on || rt.waits ? c : C.faint,
          "stroke-width": hot.has(x) ? 2.5 : 2, ...(on || rt.waits ? {} : { "stroke-dasharray": "5 4" }) }, g);
        el("text", { x: cx, y: top + 24, "text-anchor": "middle", "font-size": 18, "font-weight": 600, fill: on || rt.waits ? c : C.faint }, g).textContent = r(x);
        const label = (t, y, col) => { el("text", { x: cx, y, "text-anchor": "middle", "font-size": 13.5, "font-weight": 500, fill: col || C.muted }, g).textContent = t; };
        if (x === ORIGIN) {
          label(on ? "origin of the prefix" : k >= 0 ? "prefix gone" : "no route", cy + 8);
        } else if (!rows.length) {
          label("no route", cy + 8, hot.has(x) ? C.rose : null);
        } else {
          // Its table, a row a route: what it forwards on, keeps, set aside or pruned. Without a route, whether it waits.
          const st = on && inC.has(x) && stale(k, x, rt.best);
          rows.forEach((row, j) => {
            const y = top + 34 + j * 38;
            const col = row.waits ? (hot.has(x) ? C.rose : C.violet) : row.aside || row.pruned ? C.violet : null;
            label(j === 0 && st ? "forwards on, stale" : row.text, y + (row.p ? 10 : 18), col);
            if (row.p) chipRow(el("g", { opacity: row.op }, g), chipsOf(x, row.p, row.from), cx, y + 15, 2 * M - 12);
          });
          if (!on) label(hot.has(x) ? "no route" : "", top + H - 10, C.rose);
          else label(!sent.length ? "sends nothing" : new Set(sent.map((o) => JSON.stringify(o.path))).size > 1 ? "sends per neighbor" : `sends to ${sent.map((o) => r(o.to)).join(", ")}`, top + H - 10);
        }
        // A table per neighbor: what each table offers, at the start of its belt, "not sent" where it is not.
        if (PN && rt.tables && on && x === chosen) for (const [j, v] of Object.entries(rt.tables)) {
          if (!v.export) continue;
          const gq = geo(x, +j, LANE), [tx, ty] = at(gq, 0.16), sent = offer(k, x, +j), tg = el("g", {}, svg);
          const lx = tx + gq.nx * 20, ly = ty + gq.ny * 20;
          el("text", { x: lx, y: ly - 11, "text-anchor": "middle", "font-size": 13.5, "font-weight": 600, fill: C.muted, stroke: C.card, "stroke-width": 3, "paint-order": "stroke" }, tg).textContent = `${OBGP ? "threshold for" : "for"} r${j}${sent ? "" : ", not sent"}`;
          chipRow(tg, [ASN[x], ...bare(v.export)], lx, ly - 9, (v.export.length + 1) * 25);
        }
        if ((inst.ibgp || []).some((b) => (b.reflectors || []).includes(x))) el("text", { x: cx - M + 9, y: top + 15, "font-size": 13.5, "font-weight": 700, fill: C.role }, g).textContent = "RR";
        if ((inst.route_servers || []).includes(x)) el("text", { x: cx - M + 9, y: top + 15, "font-size": 13.5, "font-weight": 700, fill: C.role }, g).textContent = "RS";
        g.style.cursor = "pointer";
        g.addEventListener("click", () => { chosen = x; go(pos, true); });
      }
      // Every phase has its bubble: what leaves, what arrives and what the router does, or the change from outside.
      // While the timeline is dragged none: placing a bubble measures the whole map.
      if (opts.kf === undefined && !opts.scrub) {
        if (opts.ph === "send") for (const [x, items] of sendItems(k)) drawBubble(x, items);
        else if (k < 0) drawBubble(ORIGIN, "Has the prefix. Nobody else has a route yet.");
        else if (isMsg(steps[k])) drawBubble(steps[k].to, arrivalText(k));
        else drawBubble(...eventItems(steps[k].event));
      }
    }

    // ---- Bubbles ----
    // Where a bubble goes: away from the middle of the map, beside, below or above its router, wherever it covers
    // no card, no belt, no label and no other bubble. Else where it covers least.
    let tailSide = "left";
    function side(x, w, h) {
      const vb = svg.viewBox.baseVal, [cx, cy] = POS[x], H = cardH.get(x);
      const mx = POS.reduce((t, p) => t + p[0], 0) / N, my = POS.reduce((t, p) => t + p[1], 0) / N;
      const R_ = (dy) => ({ left: cx + M + 12, top: cy - h / 2 + dy * h, tail: "left" }), L_ = (dy) => ({ left: cx - M - 12 - w, top: cy - h / 2 + dy * h, tail: "right" });
      const B_ = (dx) => ({ left: cx - w / 2 + dx * w, top: cy + H / 2 + 12, tail: "top" }), T_ = (dx) => ({ left: cx - w / 2 + dx * w, top: cy - H / 2 - 12 - h, tail: "bottom" });
      const dys = [0, -0.5, 0.5, -1, 1], dxs = [0, -0.4, 0.4], wide = Math.abs(cx - mx) > 40;
      const ends = cy > my ? [B_, T_] : [T_, B_];
      const order = wide ? (cx > mx ? [R_, ends[0], ends[1], L_] : [L_, ends[0], ends[1], R_]) : [ends[0], R_, L_, ends[1]];
      const cands = order.flatMap((f) => (f === B_ || f === T_ ? dxs : dys).map(f));
      const cards = [...cardH].map(([y, hh]) => ({ x: POS[y][0] - M - 4, y: POS[y][1] - hh / 2 - 4, w: 2 * M + 8, h: hh + 8 }));
      const others = [...svg.querySelectorAll("[data-bubble], [data-label]")].map((e) => { const b = e.getBBox(); return { x: b.x - 6, y: b.y - 6, w: b.width + 12, h: b.height + 12 }; });
      const area = (c, bs) => bs.reduce((t, b) => t + Math.max(0, Math.min(c.left + w, b.x + b.w) - Math.max(c.left, b.x)) * Math.max(0, Math.min(c.top + h, b.y + b.h) - Math.max(c.top, b.y)), 0);
      const belts = [];
      for (const [p, q] of inst.links) for (const ln of [LANE, -LANE]) { const g = geo(p, q, ln); for (let t = 0; t <= 1; t += 1 / 24) belts.push(at(g, t)); }
      const onBelt = (c) => belts.filter(([px, py]) => px > c.left - 8 && px < c.left + w + 8 && py > c.top - 8 && py < c.top + h + 8).length;
      const inside = (c) => c.left >= vb.x + 4 && c.left + w <= vb.x + vb.width - 4 && c.top >= vb.y + 4 && c.top + h <= vb.y + vb.height - 4;
      const cost = (c) => area(c, cards) * 4 + area(c, others) * 4 + onBelt(c) * 300;
      const ok = cands.filter(inside);
      const best = ok.find((c) => cost(c) === 0) || ok.map((c, i) => [cost(c) + i, c]).sort((a, b) => a[0] - b[0])[0]?.[1] || cands[0];
      tailSide = best.tail;
      return [best.left, best.top];
    }
    // A bubble of items: a text, wrapped, router names in their colour, or {chips: path} on a line of its own.
    // A small tail points at the router it speaks for.
    function drawBubble(x, items) {
      const rows = [];
      for (const it of [].concat(items)) if (typeof it === "string") for (const l of wrap(it)) rows.push({ text: l }); else rows.push(it);
      const w = Math.max(...rows.map((q) => (q.text !== undefined ? q.text.length * 7.1 : q.chips.length * 30))) + 24;
      const h = 14 + rows.reduce((t, q) => t + (q.text !== undefined ? 18 : 24), 0), [left, top] = side(x, w, h);
      const g = el("g", { class: "fadein", "data-bubble": x, filter: "url(#sim-sh)" }, svg);
      const [cx, cy] = POS[x], ty = Math.min(Math.max(cy, top + 10), top + h - 10), tx = Math.min(Math.max(cx, left + 12), left + w - 12);
      const tail = tailSide === "left" ? `M${left},${ty - 6} L${left - 7},${ty} L${left},${ty + 6} Z`
        : tailSide === "right" ? `M${left + w},${ty - 6} L${left + w + 7},${ty} L${left + w},${ty + 6} Z`
          : tailSide === "top" ? `M${tx - 6},${top} L${tx},${top - 7} L${tx + 6},${top} Z`
            : `M${tx - 6},${top + h} L${tx},${top + h + 7} L${tx + 6},${top + h} Z`;
      el("path", { d: tail, fill: C.tip }, g);
      el("rect", { x: left, y: top, width: w, height: h, rx: 8, fill: C.tip }, g);
      let y = top + 5;
      for (const q of rows) {
        if (q.text !== undefined) {
          const t = el("text", { x: left + 12, y: y + 14, "font-size": 13.5, fill: "#ffffff" }, g);
          for (const part of q.text.split(/\b(r\d+)\b/)) {
            const m = /^r(\d+)$/.exec(part), ts = el("tspan", {}, t);
            ts.textContent = part;
            if (m && +m[1] < N) { ts.setAttribute("fill", light(hue(+m[1]))); ts.setAttribute("font-weight", "700"); }
          }
          y += 18;
        } else { chipRow(g, q.chips, left + 12 + (q.chips.length * 30) / 2, y + 3, q.chips.length * 30 + 4); y += 24; }
      }
    }

    let pos = 0, timer = null, anim = 0;
    // The track: the loop in rose, the past light blue, now a mark. Drawn as runs, so a long run stays light.
    const track = parts.timeline;
    function buildTrack() {
      track.innerHTML = "";
      track.classList.add("sim-track");
      const pct = (i) => `${(100 * i) / TL.length}%`;
      const done = document.createElement("i"); done.className = "done"; track.appendChild(done);
      for (let i = 0; i < TL.length;) {
        if (!problemAt(TL[i].k).size) { i++; continue; }
        let j = i; while (j < TL.length && problemAt(TL[j].k).size) j++;
        const s = document.createElement("i"); s.className = "loop"; s.style.left = pct(i); s.style.width = pct(j - i); track.appendChild(s); i = j;
      }
      const now = document.createElement("i"); now.className = "now"; track.appendChild(now);
      track.setAttribute("aria-valuemax", String(TL.length - 1));
    }
    const pick = (e) => { const b = track.getBoundingClientRect(); return Math.max(0, Math.min(TL.length - 1, Math.floor(((e.clientX - b.left) / b.width) * TL.length))); };
    // Dragging scrubs: the map changes only when the step under the pointer does, so hovering never redraws it. At most
    // once a frame and without bubbles while dragging, the bubble of the step where the pointer lets go.
    let dragging = false, wanted = -1, frame = 0, scrubbed = false;
    track.onpointerdown = (e) => { stop(); dragging = true; scrubbed = false; track.setPointerCapture?.(e.pointerId); if (pick(e) !== pos) go(pick(e)); };
    track.onpointermove = (e) => {
      if (!dragging || pick(e) === pos) return;
      wanted = pick(e);
      if (!frame) frame = requestAnimationFrame(() => { frame = 0; if (dragging && wanted !== pos) { scrubbed = true; go(wanted, false, undefined, true); } });
    };
    track.onpointerup = track.onpointercancel = () => {
      dragging = false;
      if (frame) { cancelAnimationFrame(frame); frame = 0; if (wanted !== pos) { scrubbed = true; pos = wanted; } }
      if (scrubbed) { scrubbed = false; go(pos); }
    };
    function go(i, keep, pulse, scrub) {
      pos = i;
      const { k, ph } = TL[i];
      if (!keep && k >= 0 && isMsg(steps[k])) chosen = ph === "send" && created(k).length ? steps[created(k)[0]].from : steps[k].to;
      render(k, { ph, hideNew: ph === "arrive", scrub, ...(pulse === undefined ? {} : { pulse }) });
      const w = TL.length > 1 ? (100 * i) / TL.length : 0;
      track.querySelector(".done").style.width = `${w}%`;
      Object.assign(track.querySelector(".now").style, { left: `${w}%`, width: `${100 / TL.length}%` });
      track.setAttribute("aria-valuenow", String(i));
      parts.counter.textContent = `${i} / ${TL.length - 1}`;
      if (parts.phase) parts.phase.textContent = phaseText(i);
    }
    // One animation at a time: a new step ends the running one and counts from where it was going.
    const SPEEDS = [0.5, 1, 2, 4, 8, 16], speed = () => SPEEDS[Number(parts.speed.value)] ?? 1;
    function step(d) {
      const i = pos + d;
      if (i < 0 || i >= TL.length) return false;
      const a = TL[pos], b = TL[i], run = ++anim;
      pos = i;
      if (d > 0 && b.k > a.k && isMsg(steps[b.k])) {
        // On to the next arrival: every message moves on together, the one that arrives runs into its router, which pulses.
        const t0 = performance.now(), from = a.k, ease = (u) => u * u * (3 - 2 * u);
        const f = (now) => {
          if (run !== anim) return;
          const u = Math.min(1, Math.max(0, now - t0) / (850 / speed()));
          render(from, { kf: from + ease(u), eat: b.k });
          if (u < 1) requestAnimationFrame(f); else go(i, false, steps[b.k].to);
        };
        requestAnimationFrame(f);
      } else if (d > 0 && b.k > a.k && steps[b.k].event) {
        go(i, false, steps[b.k].event.from ?? ORIGIN);  // an event: nothing travels, its router pulses at once
      } else go(i);
      return true;
    }
    const playing = (on) => { parts.play.innerHTML = `${UI.icon(on ? "pause" : "play")}<span>${on ? "Pause" : "Play"}</span>`; };
    function stop() { clearInterval(timer); timer = null; anim++; playing(false); }
    const looping = () => parts.loop.getAttribute("aria-pressed") === "true";
    const tick = () => { if (!step(1)) { if (looping()) go(0); else stop(); } };
    parts.prev.onclick = () => { stop(); step(-1); };
    parts.next.onclick = () => { stop(); step(1); };
    parts.loop.onclick = () => parts.loop.setAttribute("aria-pressed", looping() ? "false" : "true");
    parts.play.onclick = () => {
      if (timer) return stop();
      if (pos >= TL.length - 1) go(0);
      playing(true);
      timer = setInterval(tick, 1400 / speed());
    };
    parts.speed.oninput = () => {
      parts.speedLabel.textContent = speed() === 0.5 ? "½×" : `${speed()}×`;
      if (timer) { clearInterval(timer); timer = setInterval(tick, 1400 / speed()); }
    };
    const onTheme = () => { colours(); go(pos, true); };
    document.addEventListener("lab:theme", onTheme);
    buildTrack();
    go(0, true);
    const api = {
      step, stop, go, TL, phases: () => TL.length, render,
      destroy() { stop(); document.removeEventListener("lab:theme", onTheme); if (current === api) current = null; },
    };
    current = api;
    return api;
  }

  window.SimMap = { mount, model };
})();
