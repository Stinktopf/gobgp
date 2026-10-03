// Shared by every view of a topology: the editor, the scenario preview and
// the replay. One look for routers, sessions and origins, and one default
// layout.
window.Graph = (() => {
  const css = UI.css;
  const font = "ui-sans-serif, system-ui, sans-serif";

  // Sizes in screen pixels, whatever the zoom.
  const px = (cy, n) => () => n / (cy() ? cy().zoom() : 1);

  function style(cy, { node = 12, label = 10 } = {}) {
    return [
      { selector: "node", style: {
        "background-color": css("--graph-node"), width: px(cy, node), height: px(cy, node), label: "data(id)",
        color: css("--graph-label"), "font-size": px(cy, label), "font-family": font, "text-valign": "bottom",
        "text-margin-y": px(cy, 4), "text-background-color": css("--graph-bg"), "text-background-opacity": 0.7,
        "text-background-padding": px(cy, 1), "text-background-shape": "roundrectangle",
      } },
      { selector: "node.origin", style: {
        shape: "diamond", "background-color": css("--graph-accent"), width: px(cy, node * 1.5), height: px(cy, node * 1.5),
      } },
      // A router that runs OBGP in a hybrid is a square; a ring means it holds every prefix.
      { selector: "node.obgp", style: { shape: "round-rectangle" } },
      { selector: "edge", style: { width: px(cy, 1.5), "line-color": css("--graph-edge"), "curve-style": "straight" } },
      // A Local Preference is a small pill at the end of the router that prefers.
      { selector: "edge.pref", style: {
        width: px(cy, 2), "line-color": css("--graph-accent-soft"), "source-label": pill("prefSource"), "target-label": pill("prefTarget"),
        "source-text-offset": px(cy, 26), "target-text-offset": px(cy, 26), "font-size": px(cy, 9), "font-weight": 600,
        color: css("--graph-accent"), "font-family": font,
        "text-background-color": css("--graph-bg"), "text-background-opacity": 1, "text-background-padding": px(cy, 2),
        "text-background-shape": "roundrectangle", "text-border-width": px(cy, 1), "text-border-color": css("--graph-accent-soft"),
        "text-border-opacity": 1,
      } },
      // Gao-Rexford: an arrow points from a provider to its customer, peers
      // have a dot at both ends.
      { selector: "edge.p2c", style: { "target-arrow-shape": "triangle", "target-arrow-color": css("--graph-edge"), "arrow-scale": 1.3 } },
      { selector: "edge.c2p", style: { "source-arrow-shape": "triangle", "source-arrow-color": css("--graph-edge"), "arrow-scale": 1.3 } },
      { selector: "edge.p2p", style: {
        "source-arrow-shape": "circle", "target-arrow-shape": "circle", "source-arrow-color": css("--graph-edge"),
        "target-arrow-color": css("--graph-edge"), "arrow-scale": 0.9,
      } },
      { selector: ":selected", style: {
        "underlay-color": css("--graph-accent"), "underlay-padding": px(cy, 5), "underlay-opacity": 0.25, "underlay-shape": "ellipse",
      } },
    ];
  }

  const DEFAULT_PREF = 100;  // BGP's default Local Preference
  const customPref = (pref) => pref != null && +pref !== DEFAULT_PREF;
  const pill = (end) => (e) => (customPref(e.data(end)) ? String(e.data(end)) : "");

  // What the target of a session is to its source, as the class of the edge.
  const REL = { customer: "p2c", provider: "c2p", peer: "p2p" };
  const classes = (data) => [customPref(data.prefSource) || customPref(data.prefTarget) ? "pref" : "", data.rel || ""].filter(Boolean).join(" ");

  // Sessions carry the Local Preference of both ends and their relation;
  // edges with a Local Preference other than the default have the class
  // "pref", related ones p2c, c2p or p2p.
  function elements(topology) {
    const origins = new Set(topology.roles?.origins || []);
    // Routers that run OBGP in hybrids: marked in the topology, or by the
    // modes of a run, which are null for a run in one mode.
    const runsObgp = (name) => ("modes" in topology ? (topology.modes?.[name] ?? "bgp") !== "bgp" : topology.routers[name].obgp);
    const els = Object.keys(topology.routers).map((name) => ({
      group: "nodes", data: { id: name }, classes: [origins.has(name) ? "origin" : "", runsObgp(name) ? "obgp" : ""].filter(Boolean).join(" "),
    }));
    const side = (from, to) => (topology.routers[from].neighbors || []).find((m) => m.name === to) || {};
    const pref = (from, to) => side(from, to).localPref ?? null;
    const seen = new Set();
    for (const [a, r] of Object.entries(topology.routers)) {
      for (const n of r.neighbors || []) {
        const id = [a, n.name].sort().join("|");
        if (seen.has(id) || !topology.routers[n.name]) continue;
        seen.add(id);
        const data = { id, source: a, target: n.name, prefSource: pref(a, n.name), prefTarget: pref(n.name, a), rel: REL[n.relation] ?? null };
        els.push({ group: "edges", data, classes: classes(data) });
      }
    }
    return els;
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
        const a = -Math.PI / 2 + (2 * Math.PI * i) / ring.length + (level % 2 ? 0 : Math.PI / ring.length);
        angle[n] = a;
        positions[n] = { x: radius * Math.cos(a), y: radius * Math.sin(a) };
      });
    }
    return positions;
  }

  // The initial layout of a topology without positions of its own: rings
  // around the origins for small ones, a force layout from the rings for
  // large ones. Seeded by the topology, so that the editor and every
  // preview arrange it alike, every time.
  const arranged = new WeakMap();
  function arrange(topology) {
    if (arranged.has(topology)) return arranged.get(topology);
    const names = Object.keys(topology.routers);
    let positions = rings(topology);
    if (names.length > 20 && window.cytoscape) {
      const random = Math.random;
      Math.random = seeded(names.sort().join());
      try {
        const cy = cytoscape({ headless: true, elements: elements(topology).map((e) => (e.group === "nodes" ? { ...e, position: { ...positions[e.data.id] } } : e)) });
        cy.layout({ name: "cose", animate: false, nodeRepulsion: 400000, idealEdgeLength: 120, randomize: false }).run();
        positions = Object.fromEntries(cy.nodes().map((n) => [n.id(), { ...n.position() }]));
        cy.destroy();
      } finally {
        Math.random = random;
      }
    }
    arranged.set(topology, positions);
    return positions;
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
      if (a < n.name && pos[n.name]) out += `<line x1="${pos[a].x}" y1="${pos[a].y}" x2="${pos[n.name].x}" y2="${pos[n.name].y}" stroke="var(--graph-edge)" stroke-width="${Math.max(0.5, fine) * unit}"/>`;
    }
    for (const [n, q] of Object.entries(pos)) {
      out += origins.has(n)
        ? `<rect x="${q.x - r * 1.2}" y="${q.y - r * 1.2}" width="${r * 2.4}" height="${r * 2.4}" transform="rotate(45 ${q.x} ${q.y})" fill="var(--graph-accent)"/>`
        : `<circle cx="${q.x}" cy="${q.y}" r="${r}" fill="var(--graph-node)"/>`;
    }
    svg.innerHTML = out;
    return p ? null : { viewBox: svg.getAttribute("viewBox"), body: out };  // a map is drawn again, it is quick
  }

  // A read-only view of a topology, e.g. a preview; extra styles on top.
  function view(container, topology, { node = 10, label = 10, padding = 24, styles = [] } = {}) {
    const { positions, projection } = layout(topology);
    let cy = null;
    cy = cytoscape({
      container, elements: elements(topology), autoungrabify: true, boxSelectionEnabled: false,
      layout: { name: "preset", positions, fit: false },
      style: [...style(() => cy, { node, label }), ...styles],
    });
    cy.on("zoom", () => cy.style().update());  // sizes follow the zoom
    fit(cy, padding);
    underlay(cy, container, projection);
    return cy;
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
    const keyOf = (svg) => `thumb:${svg.dataset.topology}:${stamps[svg.dataset.topology]}:${svg.clientWidth}x${svg.clientHeight}`;
    async function draw(svg) {
      const name = svg.dataset.topology, key = keyOf(svg);
      try {
        const kept = JSON.parse(localStorage.getItem(key));
        if (kept) { svg.setAttribute("viewBox", kept.viewBox); svg.setAttribute("preserveAspectRatio", "xMidYMid meet"); svg.innerHTML = kept.body; return; }
      } catch { /* private window: draw it */ }
      const response = await fetch(`/topologies/${encodeURIComponent(name)}/thumb?v=${stamps[name]}`);
      if (!response.ok) return;
      const drawn = await thumbnail(svg, await response.json());
      if (!drawn) return;
      try {
        for (const k of Object.keys(localStorage)) if (k.startsWith(`thumb:${name}:`)) localStorage.removeItem(k);  // older versions
        localStorage.setItem(key, JSON.stringify(drawn));
      } catch { /* full or private: drawn again next time */ }
    }
    const seen = new IntersectionObserver((entries) => entries.forEach((e) => {
      if (e.isIntersecting) { seen.unobserve(e.target); draw(e.target); }
    }), { rootMargin: "200px" });
    document.querySelectorAll("svg.thumb[data-topology]").forEach((svg) => seen.observe(svg));
  });

  return { px, customPref, classes, style, elements, projection, arrange, underlay, view, fit, ramp };
})();
