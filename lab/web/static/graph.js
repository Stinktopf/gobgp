// Shared by every view of a topology: the editor, the scenario preview and
// the replay. One look for routers, sessions and origins, and one default
// layout.
window.Graph = (() => {
  const css = UI.css;
  const font = "ui-sans-serif, system-ui, sans-serif";

  // Sizes in screen pixels, whatever the zoom.
  const px = (cy, n) => () => n / (cy() ? cy().zoom() : 1);

  // Router colours as on the Simulation's map, --router-1 to --router-8 in styles.css: each router has its
  // own while there are few, else all are neutral and only the meanings have colours: U of T blue a route,
  // teal a role or rule, violet waits, rose the problem. Read again when the colour scheme changes.
  const HUES = 8;
  let hues = { theme: undefined, list: [] };
  function palette() {
    const theme = document.documentElement.dataset.theme;
    if (hues.theme !== theme) hues = { theme, list: Array.from({ length: HUES }, (_, i) => css(`--router-${i + 1}`)) };
    return hues.list;
  }
  // Up to this many routers the links are belts as on the map, more are thin lines.
  const BELTS = 30;
  // The routers of a graph in their order, their count and the count of links, kept until one comes or goes.
  function order(cy) {
    let o = cy.scratch("graph-order");
    if (o) return o;
    const ids = cy.nodes().not(".as").map((n) => n.id());
    o = { count: ids.length, links: cy.edges().length, index: new Map(ids.length <= HUES ? ids.map((id, i) => [id, i]) : []) };
    cy.scratch("graph-order", o);
    if (!cy.scratch("graph-order-watched")) {
      cy.scratch("graph-order-watched", true);
      cy.on("add remove", () => cy.removeScratch("graph-order"));
    }
    return o;
  }
  // The colour of a router among few, or null.
  function hue(n) {
    const i = order(n.cy()).index.get(n.id());
    return i === undefined ? null : palette()[i];
  }
  const belts = (cy) => order(cy).count <= BELTS;
  // Links in screen pixels: belts 3, lines 1.5. Many links are fainter, so that a dense core stays a shape.
  const linkWidth = (cy) => (belts(cy) ? 3 : 1.5);
  function linkOpacity(cy) {
    const n = order(cy).links;
    return n <= 400 ? 1 : Math.max(0.2, 400 / n);
  }
  // The style of a link with a Local Preference: teal on the half at each router that prefers.
  // As data mappers, so that the editor's changes show at once; replay passes the ends itself.
  function prefFill(link, role, ends = (e) => [customPref(e.data("prefSource")), customPref(e.data("prefTarget"))]) {
    const stops = (e) => { const [s, t] = ends(e); return [s ? role : link, s ? role : link, t ? role : link, t ? role : link].join(" "); };
    return { "line-fill": "linear-gradient", "line-gradient-stop-colors": stops, "line-gradient-stop-positions": "0% 50% 50% 100%" };
  }
  // A colour token with transparency as a colour and an opacity, which Cytoscape takes apart.
  function tone(token) {
    const c = document.createElement("canvas").getContext("2d");
    c.fillStyle = css(token);
    c.fillRect(0, 0, 1, 1);
    const [r, g, b, a] = c.getImageData(0, 0, 1, 1).data;
    return { color: `rgb(${r},${g},${b})`, opacity: a / 255 };
  }
  // A router's name, its role and, for an origin, that it is one, as on the map.
  const labelOf = (n) => `${n.id()}${n.hasClass("rr") ? " RR" : ""}${n.hasClass("rs") ? " RS" : ""}${n.hasClass("origin") ? "\norigin" : ""}`;

  function style(cy, { node = 12, label = 10 } = {}) {
    const C = Object.fromEntries(["--graph-bg", "--graph-node", "--graph-label", "--graph-link", "--graph-accent", "--graph-role"].map((t) => [t, css(t)]));
    const frame = tone("--graph-as-1");
    const zoom = () => (cy() ? cy().zoom() : 1);
    // Smaller cards among many routers, so that the links between them show.
    const side = (n) => (belts(n.cy()) ? node : node * 0.75) / zoom();
    return [
      // A router: a card of the map in miniature, its border and name in its colour.
      { selector: "node", style: {
        shape: "round-rectangle", "background-color": C["--graph-bg"], "border-width": px(cy, 1.75),
        "border-color": (n) => hue(n) || C["--graph-node"], width: side, height: side, label: labelOf, "text-wrap": "wrap",
        color: (n) => hue(n) || C["--graph-label"], "font-size": px(cy, label), "font-family": font, "font-weight": 600, "text-valign": "bottom",
        "text-margin-y": px(cy, 4), "text-background-color": C["--graph-bg"], "text-background-opacity": 0.7,
        "text-background-padding": px(cy, 1), "text-background-shape": "roundrectangle",
      } },
      // A label that would cover another is hidden until a zoom makes room, see declutter.
      { selector: "node.crowded", style: { "text-opacity": 0 } },
      { selector: "node.crowded:selected", style: { "text-opacity": 1 } },
      // A router that runs OBGP in a hybrid has a double border.
      { selector: "node.obgp", style: { "border-style": "double", "border-width": px(cy, 3.5) } },
      // A link: a belt as on the map while the routers are few, else a thin line, fainter among many.
      { selector: "edge", style: {
        width: (e) => linkWidth(e.cy()) / zoom(), "line-color": C["--graph-link"], opacity: (e) => linkOpacity(e.cy()),
        "curve-style": "straight", "line-cap": "round",
      } },
      // A Local Preference is teal, as the map's rules: the half of the link at the router that prefers,
      // so that its direction shows at any size, and a tag with its value where there is room.
      { selector: "edge.pref", style: {
        ...prefFill(C["--graph-link"], C["--graph-role"]), opacity: 1,
        "source-label": pill("prefSource"), "target-label": pill("prefTarget"),
        "source-text-offset": px(cy, 30), "target-text-offset": px(cy, 30), "font-size": px(cy, 9), "font-weight": 600,
        color: C["--graph-role"], "font-family": font,
        "text-background-color": C["--graph-bg"], "text-background-opacity": 1, "text-background-padding": px(cy, 2),
        "text-background-shape": "roundrectangle", "text-border-width": px(cy, 1), "text-border-color": C["--graph-role"],
        "text-border-opacity": 1,
      } },
      // After the tag itself, which it hides where it would cover another label, see declutter.
      { selector: "edge.pref.crowded-source", style: { "source-label": "" } },
      { selector: "edge.pref.crowded-target", style: { "target-label": "" } },
      // Gao-Rexford, in teal as every rule: an arrow points from a provider to its customer, peers
      // have a dot at both ends, siblings a double line.
      { selector: "edge.p2c", style: { "target-arrow-shape": "triangle", "target-arrow-color": C["--graph-role"], "arrow-scale": (e) => (belts(e.cy()) ? 0.9 : 1) } },
      { selector: "edge.c2p", style: { "source-arrow-shape": "triangle", "source-arrow-color": C["--graph-role"], "arrow-scale": (e) => (belts(e.cy()) ? 0.9 : 1) } },
      { selector: "edge.p2p", style: {
        "source-arrow-shape": "circle", "target-arrow-shape": "circle", "source-arrow-color": C["--graph-role"],
        "target-arrow-color": C["--graph-role"], "arrow-scale": (e) => (belts(e.cy()) ? 0.7 : 0.8),
      } },
      // Two lines: the link in the background's colour inside an outline in the link's colour.
      { selector: "edge.s2s", style: { "line-color": C["--graph-bg"], width: px(cy, 1.5), "line-outline-width": px(cy, 1.5), "line-outline-color": C["--graph-link"] } },
      // An AS of several routers is a shaded area behind them, a confederation also has a dashed border, as on the map,
      // each named inside at its top left: Cytoscape puts a left label outside, the margins move it in.
      { selector: "node.as", style: {
        shape: "round-rectangle", "background-color": frame.color, "background-opacity": frame.opacity,
        "border-width": 0, padding: px(cy, 20),
        label: "data(label)", "text-valign": "top", "text-halign": "left", "text-margin-y": px(cy, label + 7),
        "text-margin-x": (n) => (String(n.data("label")).length * label * 0.6 + 8) / zoom(),
        "font-size": px(cy, label), "font-weight": 600, color: C["--graph-node"], "text-background-opacity": 0,
      } },
      { selector: "node.confed", style: { "border-width": px(cy, 1.2), "border-style": "dashed", "border-color": C["--graph-node"], padding: px(cy, 28) } },
      // A route reflector has RR after its name, a route server RS, both in teal as in the Simulation.
      { selector: "node.rr, node.rs", style: { "border-color": C["--graph-role"], color: C["--graph-role"] } },
      { selector: ":selected", style: {
        "underlay-color": C["--graph-accent"], "underlay-padding": px(cy, 5), "underlay-opacity": 0.25, "underlay-shape": "round-rectangle",
      } },
    ];
  }

  const DEFAULT_PREF = 100;  // BGP's default Local Preference
  const customPref = (pref) => pref != null && +pref !== DEFAULT_PREF;
  const pill = (end) => (e) => (customPref(e.data(end)) ? `pref ${e.data(end)}` : "");

  // What the target of a session is to its source, as the class of the edge.
  const REL = { customer: "p2c", provider: "c2p", peer: "p2p", sibling: "s2s" };
  const classes = (data) => [customPref(data.prefSource) || customPref(data.prefTarget) ? "pref" : "", data.rel || ""].filter(Boolean).join(" ");

  // Sessions carry the Local Preference of both ends and their relation;
  // edges with a Local Preference other than the default have the class
  // "pref", related ones p2c, c2p, p2p or s2s.
  function elements(topology) {
    const origins = new Set(topology.roles?.origins || []);
    // Routers that run OBGP in hybrids: marked in the topology, or by the
    // modes of a run, which are null for a run in one mode.
    const runsObgp = (name) => ("modes" in topology ? (topology.modes?.[name] ?? "bgp") !== "bgp" : topology.routers[name].obgp);
    // An AS of several routers is a frame, a parent node of its routers.
    const members = {};
    for (const [name, r] of Object.entries(topology.routers)) (members[r.asn] ||= []).push(name);
    // A confederation is a frame around those: its member ASes, or its routers alone in their AS.
    const confed = (name) => (topology.routers[name].confederation != null ? `confed-${topology.routers[name].confederation}` : undefined);
    const frame = (name) => (members[topology.routers[name].asn]?.length > 1 ? `as-${topology.routers[name].asn}` : confed(name));
    const reflector = (name) => (topology.routers[name].neighbors || []).some((m) => m.rrClient);
    const server = (name) => (topology.routers[name].neighbors || []).some((m) => m.rsClient);
    const confeds = [...new Set(Object.keys(topology.routers).map(confed).filter(Boolean))];
    const els = confeds.map((id) => ({
      group: "nodes", data: { id, label: `Confederation ${id.slice(7)}` }, classes: "as confed", selectable: false, grabbable: false,
    }));
    els.push(...Object.entries(members).filter(([, m]) => m.length > 1).map(([asn, m]) => ({
      group: "nodes", data: { id: `as-${asn}`, label: `AS ${asn}`, parent: confed(m[0]) }, classes: "as", selectable: false, grabbable: false,
    })));
    els.push(...Object.keys(topology.routers).map((name) => ({
      group: "nodes", data: { id: name, parent: frame(name) },
      classes: [origins.has(name) ? "origin" : "", runsObgp(name) ? "obgp" : "", reflector(name) ? "rr" : "", server(name) ? "rs" : ""].filter(Boolean).join(" "),
    })));
    const side = (from, to) => (topology.routers[from].neighbors || []).find((m) => m.name === to) || {};
    const pref = (from, to) => side(from, to).localPref ?? null;
    const seen = new Set();
    for (const [a, r] of Object.entries(topology.routers)) {
      for (const n of r.neighbors || []) {
        const id = [a, n.name].sort().join("|");
        if (seen.has(id) || !topology.routers[n.name]) continue;
        seen.add(id);
        const data = { id, source: a, target: n.name, prefSource: pref(a, n.name), prefTarget: pref(n.name, a), rel: REL[n.relation] ?? null,
                       rrSource: !!side(a, n.name).rrClient, rrTarget: !!side(n.name, a).rrClient,
                       medSource: side(a, n.name).med ?? null, medTarget: side(n.name, a).med ?? null,
                       viaSource: side(a, n.name).denyVia ?? null, viaTarget: side(n.name, a).denyVia ?? null,
                       tagSource: side(a, n.name).tag ?? null, tagTarget: side(n.name, a).tag ?? null,
                       partialSource: !!side(a, n.name).partialTransit, partialTarget: !!side(n.name, a).partialTransit };
        const ibgp = r.asn === topology.routers[n.name].asn;
        els.push({ group: "edges", data, classes: [classes(data), ibgp ? "ibgp" : ""].filter(Boolean).join(" ") });
      }
    }
    return els;
  }

  // The routers of a topology as the editor saves them: what it edits from
  // the graph, the rest kept as the file had it. nodes are {id, asn,
  // routerId, location, obgp, position}, and leak, confederation and igp
  // once edited; edges {a, b, rel, prefA, prefB, rrA, rrB}, and medA, medB
  // once edited; rel what b is to a. Pure, for tests (tests/test_web_js.py).
  const MANAGED = new Set(["asn", "routerId", "neighbors", "location", "obgp", "position"]);
  const OF = { p2c: ["customer", "provider"], c2p: ["provider", "customer"], p2p: ["peer", "peer"], s2s: ["sibling", "sibling"] };

  function serialize(original, nodes, edges) {
    const out = {};
    const ids = new Set(nodes.map((n) => n.id));
    for (const n of nodes) {
      const kept = Object.fromEntries(Object.entries(original[n.id] || {}).filter(([k]) => !MANAGED.has(k)));
      if (kept.igp) kept.igp = kept.igp.filter((link) => ids.has(link.name));
      if (kept.igp && !kept.igp.length) delete kept.igp;
      if (n.leak !== undefined) n.leak ? (kept.leak = true) : delete kept.leak;
      if (n.confederation !== undefined) n.confederation != null ? (kept.confederation = +n.confederation) : delete kept.confederation;
      if (n.igp !== undefined) {
        const links = (n.igp || []).filter((link) => ids.has(link.name) && link.cost > 0);
        links.length ? (kept.igp = links) : delete kept.igp;
      }
      const r = { asn: +n.asn, routerId: n.routerId, ...kept, neighbors: [] };
      if (n.location) r.location = n.location;
      if (n.obgp) r.obgp = true;
      if (n.position) r.position = n.position;
      out[n.id] = r;
    }
    // The AS a router sees its peer in: the confederation from outside it (lab/topology.py seen_as).
    const seenAs = (self, peer) => {
      const mine = out[self].confederation, theirs = out[peer].confederation;
      return theirs != null && theirs !== mine ? +theirs : out[peer].asn;
    };
    // Of a neighbor, what the graph does not hold stays as the file had it, e.g. MED, denyVia and tag.
    const EDITED = new Set(["name", "peerAs", "localPref", "relation", "rrClient", "rsClient", "partialTransit"]);
    const before = (self, peer) => (original[self]?.neighbors || []).find((m) => m.name === peer) || {};
    // A route server serves its neighbors in other ASes and confederations; a router not edited keeps the file's.
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const serves = (self, peer) => {
      const rs = byId[self]?.rs ?? !!before(self, peer).rsClient;
      const within = out[self].asn === out[peer].asn || (out[self].confederation != null && out[self].confederation === out[peer].confederation);
      return rs && !within;
    };
    const side = (self, peer, pref, relation, client, med, via, tag, partial) => {
      const kept = Object.fromEntries(Object.entries(before(self, peer)).filter(([k]) => !EDITED.has(k)));
      if (med !== undefined) med != null ? (kept.med = +med) : delete kept.med;
      if (via !== undefined) via != null ? (kept.denyVia = +via) : delete kept.denyVia;
      if (tag !== undefined) tag != null ? (kept.tag = String(tag)) : delete kept.tag;
      return { name: peer, peerAs: seenAs(self, peer), ...(pref ? { localPref: +pref } : {}), ...(relation ? { relation } : {}),
               ...(client ? { rrClient: true } : {}), ...(serves(self, peer) ? { rsClient: true } : {}),
               ...(partial && relation === "customer" ? { partialTransit: true } : {}), ...kept };
    };
    for (const e of edges) {
      const [ofB, ofA] = OF[e.rel] || [];
      out[e.a].neighbors.push(side(e.a, e.b, e.prefA, ofB, e.rrA, e.medA, e.viaA, e.tagA, e.partialA));
      out[e.b].neighbors.push(side(e.b, e.a, e.prefB, ofA, e.rrB, e.medB, e.viaB, e.tagB, e.partialB));
    }
    return out;
  }

  // Equirectangular around a centre, in pixels; the map uses the same.
  function projection(locations) {
    const lat0 = locations.reduce((s, l) => s + l.lat, 0) / locations.length;
    const lon0 = locations.reduce((s, l) => s + l.lon, 0) / locations.length;
    const k = Math.cos((lat0 * Math.PI) / 180), scale = 100;
    return {
      lon0,
      project: (l) => ({ x: (l.lon - lon0) * k * scale, y: (lat0 - l.lat) * scale }),
      unproject: (p) => ({ lat: +(lat0 - p.y / scale).toFixed(2), lon: +(lon0 + p.x / scale / k).toFixed(2) }),
    };
  }

  // Routers in rings by their distance in hops from the origins; each ring
  // follows the angles of the inner neighbours, which keeps edges short.
  function rings(topology) {
    const names = Object.keys(topology.routers);
    if (!names.length) return {};
    const neighbors = Object.fromEntries(names.map((n) => [n, (topology.routers[n].neighbors || []).map((m) => m.name).filter((m) => topology.routers[m])]));
    let start = (topology.roles?.origins || []).filter((n) => topology.routers[n]);
    if (!start.length) start = [names.reduce((a, b) => (neighbors[b].length > neighbors[a].length ? b : a), names[0])];
    const hops = Object.fromEntries(start.map((n) => [n, 0]));
    const queue = [...start];
    while (queue.length) {
      const n = queue.shift();
      for (const m of neighbors[n]) if (hops[m] == null) { hops[m] = hops[n] + 1; queue.push(m); }
    }
    const far = Math.max(0, ...Object.values(hops));
    for (const n of names) if (hops[n] == null) hops[n] = far + 1;  // not connected
    const angle = {}, positions = {}, R = 110;
    const levels = Math.max(...Object.values(hops));
    for (let level = 0; level <= levels; level++) {
      const ring = names.filter((n) => hops[n] === level);
      if (level === 0 && ring.length === 1) { positions[ring[0]] = { x: 0, y: 0 }; angle[ring[0]] = -Math.PI / 2; continue; }
      const inner = (n) => neighbors[n].filter((m) => hops[m] < level && angle[m] != null).map((m) => angle[m]);
      const mean = (as) => (as.length ? Math.atan2(as.reduce((s, a) => s + Math.sin(a), 0), as.reduce((s, a) => s + Math.cos(a), 0)) : 0);
      ring.sort((a, b) => mean(inner(a)) - mean(inner(b)) || a.localeCompare(b));
      const radius = level === 0 ? R / 2 : level * R;
      ring.forEach((n, i) => {
        let a = -Math.PI / 2 + (2 * Math.PI * i) / ring.length + (level % 2 ? 0 : Math.PI / ring.length);
        // Two around the origin stand below it, 60° apart: a triangle of equal sides, not a line through the origin.
        if (ring.length === 2 && level === 1) a = Math.PI / 2 + (i ? -1 : 1) * Math.PI / 6;
        // A router alone on its ring goes where its inner neighbours are, beside them where they lie opposite.
        if (ring.length === 1 && level > 0) {
          const as = inner(n), sx = as.reduce((t, x) => t + Math.cos(x), 0), sy = as.reduce((t, x) => t + Math.sin(x), 0);
          if (as.length) a = Math.hypot(sx, sy) > 1e-6 ? Math.atan2(sy, sx) : as[0] + Math.PI / 2;
        }
        angle[n] = a;
        positions[n] = { x: radius * Math.cos(a), y: radius * Math.sin(a) };
      });
    }
    return positions;
  }

  // Rings, with the routers of a frame together: an AS of several routers or
  // a confederation is one point of the rings, its routers in a small circle
  // around it, so that frames do not overlap.
  function grouped(topology) {
    const names = Object.keys(topology.routers);
    const count = {};
    for (const n of names) count[topology.routers[n].asn] = (count[topology.routers[n].asn] || 0) + 1;
    const group = (n) => {
      const r = topology.routers[n];
      return r.confederation != null ? `confed ${r.confederation}` : count[r.asn] > 1 ? `as ${r.asn}` : n;
    };
    const members = {};
    for (const n of names) (members[group(n)] ||= []).push(n);
    if (Object.keys(members).length === names.length) return rings(topology);
    const contracted = { roles: { origins: [...new Set((topology.roles?.origins || []).filter((n) => topology.routers[n]).map(group))] }, routers: {} };
    for (const [g, ms] of Object.entries(members)) {
      const near = new Set(ms.flatMap((n) => (topology.routers[n].neighbors || []).map((m) => m.name)).filter((m) => topology.routers[m]).map(group));
      near.delete(g);
      contracted.routers[g] = { neighbors: [...near].map((name) => ({ name })) };
    }
    const centres = rings(contracted), out = {};
    for (const [g, ms] of Object.entries(members)) {
      const c = centres[g], spread = 1.6;  // room between the frames
      if (ms.length === 1) { out[ms[0]] = { x: c.x * spread, y: c.y * spread }; continue; }
      const radius = 22 + 9 * ms.length;
      [...ms].sort().forEach((n, i) => {
        const a = (ms.length === 2 ? Math.PI : -Math.PI / 2) + (2 * Math.PI * i) / ms.length;  // two side by side
        out[n] = { x: c.x * spread + radius * Math.cos(a), y: c.y * spread + radius * Math.sin(a) };
      });
    }
    return out;
  }

  // The initial layout of a topology without positions of its own: rings
  // around the origins for small ones, a force layout from the rings for
  // large ones. Seeded by the topology, so that the editor and every
  // preview arrange it alike, every time.
  const arranged = new WeakMap();
  function arrange(topology) {
    if (arranged.has(topology)) return arranged.get(topology);
    const names = Object.keys(topology.routers);
    let positions = grouped(topology);
    if (names.length > 20 && window.cytoscape) {
      const random = Math.random;
      Math.random = seeded(names.sort().join());
      try {
        const cy = cytoscape({ headless: true, elements: elements(topology).map((e) => (e.group === "nodes" ? { ...e, position: { ...positions[e.data.id] } } : e)) });
        cy.layout({ name: "cose", animate: false, nodeRepulsion: 400000, idealEdgeLength: 120, randomize: false }).run();
        positions = Object.fromEntries(cy.nodes().not(".as").map((n) => [n.id(), { ...n.position() }]));
        cy.destroy();
      } finally {
        Math.random = random;
      }
    }
    if (names.length <= 20) positions = untangle(topology, positions);
    arranged.set(topology, positions);
    return positions;
  }

  // No link may pass over a router it does not end at, as two routers on
  // opposite sides of a ring around the origin would: the router is moved
  // off the link, or for an origin, which stays in the middle, the link.
  const CLEAR = 24;
  function untangle(topology, positions) {
    const out = Object.fromEntries(Object.entries(positions).map(([n, p]) => [n, { ...p }]));
    const origins = new Set(topology.roles?.origins || []);
    const links = [];
    for (const a of Object.keys(out).sort())
      for (const { name: b } of topology.routers[a]?.neighbors || []) if (out[b] && a < b) links.push([a, b]);
    for (let round = 0; round < 20; round++) {
      let moved = false;
      for (const [a, b] of links) {
        for (const c of Object.keys(out).sort()) {
          if (c === a || c === b) continue;
          const p = out[a], q = out[b], r = out[c];
          const dx = q.x - p.x, dy = q.y - p.y, len = Math.hypot(dx, dy);
          if (!len) continue;
          const t = ((r.x - p.x) * dx + (r.y - p.y) * dy) / (len * len);
          if (t <= 0 || t >= 1) continue;
          const side = ((r.x - p.x) * dy - (r.y - p.y) * dx) / len;  // signed distance of c from the link
          if (Math.abs(side) >= CLEAR) continue;
          const nx = dy / len, ny = -dx / len, push = CLEAR * 1.5;
          if (origins.has(c)) {  // the link moves away from the origin
            const by = (side > 0 ? -1 : 1) * (push + Math.abs(side));
            for (const e of [a, b]) out[e] = { x: out[e].x + nx * by, y: out[e].y + ny * by };
          } else {
            const by = (side >= 0 ? 1 : -1) * (push - Math.abs(side));
            out[c] = { x: r.x + nx * by, y: r.y + ny * by };
          }
          moved = true;
        }
      }
      if (!moved) break;
    }
    return out;
  }

  // Random numbers from a seed (mulberry32).
  function seeded(text) {
    let s = [...text].reduce((h, ch) => Math.imul(h ^ ch.charCodeAt(0), 16777619), 2166136261) >>> 0;
    return () => {
      s = (s + 0x6d2b79f5) >>> 0;
      let t = s;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // How a preview shows a topology: on the map when every router has a
  // location, else at its editor positions, else arranged.
  function layout(topology) {
    const routers = Object.entries(topology.routers);
    const all = (key) => routers.length && routers.every(([, r]) => r[key]);
    if (all("location")) {
      const p = projection(routers.map(([, r]) => r.location));
      return { positions: Object.fromEntries(routers.map(([n, r]) => [n, p.project(r.location)])), projection: p };
    }
    if (all("position")) return { positions: Object.fromEntries(routers.map(([n, r]) => [n, { ...r.position }])), projection: null };
    return { positions: arrange(topology), projection: null };
  }

  // Country outlines as SVG paths in the coordinates of a projection,
  // each shifted by 360° to the side of the routers.
  let world = null;
  async function map(p) {
    world ||= fetch("/static/world.json").then((r) => (r.ok ? r.json() : Promise.reject(new Error(r.status))));
    let asset;
    try {
      asset = await world;
    } catch {
      world = null;  // tried again next time
      return "";
    }
    return asset.rings.map((ring) => {
      const shift = Math.round((p.lon0 - ring[0]) / 360) * 360;
      let d = "";
      for (let i = 0; i < ring.length; i += 2) {
        const { x, y } = p.project({ lon: ring[i] + shift, lat: ring[i + 1] });
        d += `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
      }
      return `<path d="${d}Z" fill="var(--map-land)" stroke="var(--map-border)" stroke-width="1" vector-effect="non-scaling-stroke"/>`;
    }).join("");
  }

  // A map under a cytoscape graph, following its pan and zoom. The latest
  // call wins when the map arrives late.
  async function underlay(cy, container, p) {
    const call = (container.dataset.underlay = String(+(container.dataset.underlay || 0) + 1));
    const paths = p ? await map(p) : "";
    if (container.dataset.underlay !== call) return;
    container.querySelector("svg.map-underlay")?.remove();
    if (!p) return;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "map-underlay pointer-events-none absolute inset-0 h-full w-full");
    svg.innerHTML = `<g>${paths}</g>`;
    container.style.position ||= "relative";
    container.prepend(svg);
    const sync = () => svg.firstChild.setAttribute("transform", `translate(${cy.pan().x},${cy.pan().y}) scale(${cy.zoom()})`);
    cy.on("viewport", sync);
    sync();
  }

  // A small drawing of a topology into an <svg>: sessions, routers, origins,
  // and the map under topologies with locations. Returns what it drew, to keep.
  async function thumbnail(svg, topology) {
    // The page sends every session once; the layout wants both sides.
    for (const [a, r] of Object.entries(topology.routers)) {
      for (const n of [...(r.neighbors || [])]) {
        const other = topology.routers[n.name];
        if (other) (other.neighbors ||= []).push({ name: a });
      }
    }
    const { positions: pos, projection: p } = layout(topology);
    if (!Object.keys(pos).length) return;
    const xs = Object.values(pos).map((q) => q.x), ys = Object.values(pos).map((q) => q.y);
    const w = Math.max(1, Math.max(...xs) - Math.min(...xs)), h = Math.max(1, Math.max(...ys) - Math.min(...ys));
    svg.setAttribute("viewBox", `${Math.min(...xs) - w * 0.08} ${Math.min(...ys) - h * 0.12} ${w * 1.16} ${h * 1.24}`);
    svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
    // Marks of the same size on screen, whatever the extent of the network,
    // and finer in small drawings.
    const box = svg.viewBox.baseVal, unit = 1 / Math.min(svg.clientWidth / box.width, svg.clientHeight / box.height);
    const fine = Math.min(1, svg.clientHeight / 100);
    const r = Math.max(1.1, 2.6 * fine) * unit, origins = new Set(topology.roles?.origins || []);
    let out = p ? await map(p) : "";
    for (const [a, router] of Object.entries(topology.routers)) for (const n of router.neighbors || []) {
      if (a < n.name && pos[n.name]) out += `<line x1="${pos[a].x}" y1="${pos[a].y}" x2="${pos[n.name].x}" y2="${pos[n.name].y}" stroke="var(--graph-link)" stroke-width="${Math.max(0.5, fine) * unit}"/>`;
    }
    // Routers as small rounded squares, the origins in U of T blue: too small for the word the larger views write.
    const square = (q, s, fill) => `<rect x="${q.x - s}" y="${q.y - s}" width="${2 * s}" height="${2 * s}" rx="${s * 0.45}" fill="${fill}"/>`;
    for (const [n, q] of Object.entries(pos)) if (!origins.has(n)) out += square(q, r * 0.9, "var(--graph-node)");
    for (const [n, q] of Object.entries(pos)) if (origins.has(n)) out += square(q, r * 1.25, "var(--graph-accent)");
    svg.innerHTML = out;
    return p ? null : { viewBox: svg.getAttribute("viewBox"), body: out };  // a map is drawn again, it is quick
  }

  // A read-only view of a topology, e.g. a preview; extra styles on top.
  function view(container, topology, { node = 10, label = 10, padding = 24, styles = [], maxZoom = 1.6, keyed = true } = {}) {
    const { positions, projection } = layout(topology);
    let cy = null;
    cy = cytoscape({
      container, elements: elements(topology), autoungrabify: true, boxSelectionEnabled: false,
      layout: { name: "preset", positions, fit: false },
      style: [...style(() => cy, { node, label }), ...styles],
    });
    cy.on("zoom", () => cy.style().update());  // sizes follow the zoom
    fit(cy, padding, maxZoom);
    underlay(cy, container, projection);
    declutter(cy, label);
    // Under the graph what its marks mean, once per container, unless keyed is false: graphs side by side share one.
    const key = container.nextElementSibling?.classList.contains("graph-legend") ? container.nextElementSibling : null;
    const shown = legend(cy, { inline: true });
    shown.classList.add("px-1", "pt-2");
    if (keyed && shown.children.length) key ? key.replaceWith(shown) : container.after(shown);
    else key?.remove();
    return cy;
  }

  // What the marks of a graph mean, only those it shows, or with always the
  // ones every topology may have too: one list for the editor, the scenario
  // preview and the replay. inline lays it out as a row under a graph.
  function legend(cy, { always = false, inline = false } = {}) {
    const ul = document.createElement("ul");
    ul.className = inline ? "graph-legend muted flex flex-wrap gap-x-4 gap-y-1 text-xs" : "graph-legend muted space-y-2 text-xs";
    const swatch = (style, text = "") => { const e = document.createElement("span"); e.className = "inline-block shrink-0 text-center leading-none whitespace-nowrap"; e.textContent = text; Object.assign(e.style, style); return e; };
    const has = (selector) => always || cy.$(selector).length > 0;
    const teal = { color: "var(--graph-role)", fontWeight: "700" };
    // The origins are named on the graph, as on the Simulation's map, so they need no entry.
    const items = [
      [has("node.obgp"), swatch({ width: "11px", height: "11px", border: "3px double var(--graph-node)", borderRadius: "3px", margin: "0 3px" }), "OBGP in hybrids"],
      [has("edge.pref"), swatch({ padding: "1px 4px", border: "1px solid var(--graph-role)", borderRadius: "999px", ...teal, fontSize: "12px", lineHeight: "1" }, "pref"), "Local Preference, at the router that prefers"],
      [has("edge.p2c, edge.c2p"), swatch({ width: "17px", ...teal }, "→"), "Provider to customer"],
      [has("edge.p2p"), swatch({ width: "17px", ...teal }, "•–•"), "Peers"],
      [has("edge.s2s"), swatch({ width: "17px" }, "═"), "Siblings, one organization"],
      [cy.$("node.as").not(".confed").length > 0, swatch({ width: "17px", height: "11px", background: "var(--graph-as-1)", borderRadius: "3px" }), "AS of several routers"],
      [cy.$("node.confed").length > 0, swatch({ width: "17px", height: "11px", background: "var(--graph-as-1)", border: "1px dashed var(--graph-node)", borderRadius: "3px" }), "Confederation"],
      [cy.$("node.rr").length > 0, swatch({ width: "17px", ...teal }, "RR"), "Route reflector"],
      [cy.$("node.rs").length > 0, swatch({ width: "17px", ...teal }, "RS"), "Route server"],
    ];
    for (const [shown, mark, text] of items) {
      if (!shown) continue;
      const li = document.createElement("li");
      li.className = "flex items-center gap-2";
      const t = document.createElement("span");
      t.textContent = text;
      li.append(mark, t);
      ul.append(li);
    }
    return ul;
  }

  // Hides the labels that would cover routers or other labels, as a map does:
  // origins first, then routers with the most sessions, then the Local
  // Preferences at the ends of sessions. Again after every zoom and move,
  // and when a view changes the routers' sizes: cy.scratch("declutter")().
  let measure = null;
  const tagWidth = (text) => {
    measure ||= document.createElement("canvas").getContext("2d");
    measure.font = `600 9px ${font}`;
    return measure.measureText(text).width + 6;  // with its padding and border
  };
  function declutter(cy, label = 10) {
    const place = () => {
      const routers = cy.nodes().not(".as");
      const placed = routers.map((n) => {
        const p = n.renderedPosition(), r = n.renderedWidth() / 2;
        return { x1: p.x - r, x2: p.x + r, y1: p.y - r, y2: p.y + r };
      });
      // Frames keep their label: it sits above them, not where the box below assumes.
      cy.batch(() => routers.sort((a, b) => b.hasClass("origin") - a.hasClass("origin") || b.degree() - a.degree()).forEach((n) => {
        const lines = labelOf(n).split("\n"), p = n.renderedPosition(), w = Math.max(...lines.map((l) => l.length)) * label * 0.6, h = lines.length * (label + 2);
        const box = { x1: p.x - w / 2, x2: p.x + w / 2, y1: p.y + n.renderedWidth() / 2 + 2, y2: p.y + n.renderedWidth() / 2 + 2 + h };  // below its own card
        const covers = placed.some((o) => box.x1 < o.x2 && o.x1 < box.x2 && box.y1 < o.y2 && o.y1 < box.y2);
        n.toggleClass("crowded", covers);
        if (!covers) placed.push(box);
      }));
      const zoom = cy.zoom(), pan = cy.pan(), rendered = (p) => ({ x: p.x * zoom + pan.x, y: p.y * zoom + pan.y });
      cy.batch(() => cy.edges(".pref").forEach((e) => {
        const s = rendered(e.sourceEndpoint()), t = rendered(e.targetEndpoint()), d = Math.hypot(t.x - s.x, t.y - s.y) || 1;
        for (const [end, from, sign] of [["source", s, 1], ["target", t, -1]]) {
          const text = pill(`pref${end[0].toUpperCase()}${end.slice(1)}`)(e);
          // Where the tag sits: 30 px along the session from where it leaves the card, as the style puts it,
          // not from the router's centre, which put the tag over its own card and name.
          const x = from.x + (sign * 30 * (t.x - s.x)) / d, y = from.y + (sign * 30 * (t.y - s.y)) / d, w = tagWidth(text);
          const box = { x1: x - w / 2, x2: x + w / 2, y1: y - 7, y2: y + 7 };
          const covers = !!text && placed.some((o) => box.x1 < o.x2 && o.x1 < box.x2 && box.y1 < o.y2 && o.y1 < box.y2);
          e.toggleClass(`crowded-${end}`, covers);
          if (text && !covers) placed.push(box);
        }
      }));
    };
    // At most every 100 ms, also while a zoom or a replay goes on.
    let pending = false;
    const soon = () => {
      if (pending) return;
      pending = true;
      setTimeout(() => { pending = false; if (!cy.destroyed()) place(); }, 100);
    };
    cy.on("zoom position add remove data", soon);
    cy.scratch("declutter", soon);
    place();
  }

  // Keeps small topologies from being blown up to the whole view.
  function fit(cy, padding = 40, max = 1.6) {
    cy.fit(undefined, padding);
    if (cy.zoom() > max) cy.zoom({ level: max, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    cy.center();
  }

  function rgb(color) {
    const c = document.createElement("canvas").getContext("2d");
    c.fillStyle = color;
    c.fillRect(0, 0, 1, 1);
    return [...c.getImageData(0, 0, 1, 1).data.slice(0, 3)];
  }
  // Colour between two colours of the tokens, 0 ≤ v ≤ 1.
  function ramp(from, to) {
    const a = rgb(css(from)), b = rgb(css(to));
    return (v) => `rgb(${a.map((x, i) => Math.round(x + (b[i] - x) * Math.max(0, Math.min(1, v)))).join(",")})`;
  }

  // Thumbnails: svg.thumb[data-topology], drawn once they come into view. A
  // drawing is kept in the browser until its topology changes, by the
  // version in #thumbs; only then its data is fetched and laid out again.
  addEventListener("DOMContentLoaded", () => {
    const data = document.getElementById("thumbs");
    if (!data) return;
    const stamps = JSON.parse(data.textContent);
    // DRAWING counts the changes of the look and of what a preview gets: a drawing of an older look is
    // drawn again, and its data fetched anew, which the browser keeps a day under the same address.
    const DRAWING = 4;
    const keyOf = (svg) => `thumb:${svg.dataset.topology}:${stamps[svg.dataset.topology]}:${DRAWING}:${svg.clientWidth}x${svg.clientHeight}`;
    async function draw(svg) {
      const name = svg.dataset.topology, key = keyOf(svg);
      const kept = UI.stored(key, null);
      if (kept) { svg.setAttribute("viewBox", kept.viewBox); svg.setAttribute("preserveAspectRatio", "xMidYMid meet"); svg.innerHTML = kept.body; return; }
      const response = await fetch(`/topologies/${encodeURIComponent(name)}/thumb?v=${stamps[name]}&d=${DRAWING}`);
      if (!response.ok) return;
      const drawn = await thumbnail(svg, await response.json());
      if (!drawn) return;
      try {  // a thumbnail of this topology at another version or size is replaced
        for (const k of Object.keys(localStorage)) if (k.startsWith(`thumb:${name}:`)) localStorage.removeItem(k);
      } catch { /* private window */ }
      UI.store(key, drawn);  // full or private: drawn again next time
    }
    const seen = new IntersectionObserver((entries) => entries.forEach((e) => {
      if (e.isIntersecting) { seen.unobserve(e.target); draw(e.target); }
    }), { rootMargin: "200px" });
    document.querySelectorAll("svg.thumb[data-topology]").forEach((svg) => seen.observe(svg));
  });

  return { px, customPref, classes, style, elements, projection, arrange, underlay, view, fit, declutter, ramp, serialize, legend, hue, belts, linkWidth, linkOpacity, prefFill };
})();
