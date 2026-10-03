// Topology editor. Routers are nodes, BGP sessions are edges. A Local
// Preference belongs to one end of a session: the router at that end
// prefers routes learned from the other end, so it is shown at that end.
// A session may relate its ends as provider and customer, or as peers.
(() => {
  const data = JSON.parse(document.getElementById("topology-data").textContent);
  const $ = (id) => document.getElementById(id);
  const { css, el } = UI;
  const original = window.TOPOLOGY_NAME;
  const NAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
  // What the target of a session is to its source, and the source to its target, by its relation.
  const OF_TARGET = { p2c: "customer", c2p: "provider", p2p: "peer" }, OF_SOURCE = { p2c: "provider", c2p: "customer", p2p: "peer" };
  let projection = null;      // of the map, made when the map is first shown
  let mode = "graph";
  let connecting = false;
  let connectFrom = null;
  // Roles name groups of routers for the scenarios; origins announce the prefixes.
  const roles = Object.fromEntries(Object.entries(data.roles || {}).map(([k, v]) => [k, [...v]]));
  roles.origins ||= [];
  // Positions of the graph view. A topology without its own is arranged
  // once, as every preview shows it; that counts as unchanged until saved.
  const initial = Object.values(data.routers).every((r) => r.position) ? {} : Graph.arrange(data);
  const graphPositions = Object.fromEntries(Object.entries(data.routers).map(([n, r]) => [n, { ...(r.position || initial[n]) }]));

  // Model and elements

  function elements() {
    return Graph.elements(data).map((e) => {
      if (e.group === "nodes") {
        const r = data.routers[e.data.id];
        return { ...e, data: { ...e.data, asn: r.asn, routerId: r.routerId, location: r.location || null } };
      }
      return e;
    });
  }

  function routers() {
    const out = {};
    cy.nodes().forEach((n) => {
      const r = { asn: +n.data("asn"), routerId: n.data("routerId"), neighbors: [] };
      if (n.data("location")) r.location = n.data("location");
      if (n.hasClass("obgp")) r.obgp = true;
      if (graphPositions[n.id()]) r.position = graphPositions[n.id()];
      out[n.id()] = r;
    });
    // What the other end is to each end, by the relation of the edge.
    cy.edges().forEach((e) => {
      const a = e.source(), b = e.target(), rel = e.data("rel");
      const side = (peer, pref, relation) => ({ name: peer.id(), peerAs: +peer.data("asn"), ...(pref ? { localPref: +pref } : {}), ...(relation ? { relation } : {}) });
      out[a.id()].neighbors.push(side(b, e.data("prefSource"), OF_TARGET[rel]));
      out[b.id()].neighbors.push(side(a, e.data("prefTarget"), OF_SOURCE[rel]));
    });
    return out;
  }

  // Graph

  let cy = null;
  cy = cytoscape({ container: $("graph"), elements: elements(), minZoom: 0.05, maxZoom: 4, style: style() });

  function style() {
    return [
      ...Graph.style(() => cy, { node: 13, label: 11 }),
      { selector: "node.from", style: { "underlay-color": css("--graph-accent"), "underlay-padding": Graph.px(() => cy, 7), "underlay-opacity": 0.4 } },
    ];
  }

  const custom = Graph.customPref;
  const mark = () => cy.edges().forEach((e) => e.classes(Graph.classes(e.data())));
  mark();

  // Modes

  const located = () => cy.nodes().length > 0 && cy.nodes().every((n) => n.data("location"));

  async function setMode(next) {
    if (next === "map") {
      if (!located()) return;
      if (!projection) {
        projection = Graph.projection(cy.nodes().map((n) => n.data("location")));
        await Graph.underlay(cy, $("graph").parentNode, projection);
      }
      cy.nodes().forEach((n) => n.position(projection.project(n.data("location"))));
    } else {
      cy.nodes().forEach((n) => n.position(graphPositions[n.id()]));
    }
    mode = next;
    $("graph").parentNode.querySelector("svg.map-underlay")?.classList.toggle("hidden", mode !== "map");
    // On the map the routers sit at their places, so the button only resets the view.
    $("layout").dataset.tip = mode === "map" ? "Reset the view" : "Auto layout";
    $("layout").setAttribute("aria-label", $("layout").dataset.tip);
    Graph.fit(cy, 48, 1.5);
    renderModes();
  }

  // The initial layout again, for the topology as it is now.
  function arrange() {
    const positions = Graph.arrange({ routers: routers(), roles });
    cy.nodes().forEach((n) => n.position(positions[n.id()]));
    cy.nodes().forEach((n) => { graphPositions[n.id()] = { ...n.position() }; });
    Graph.fit(cy, 48, 1.5);
  }

  // The map is offered only while every router has a location.
  function renderModes() {
    $("modes").hidden = !located();
    document.querySelectorAll("#modes button").forEach((b) => b.setAttribute("aria-pressed", b.dataset.mode === mode));
    $("connect").setAttribute("aria-pressed", connecting);
    $("hint").textContent = connectFrom ? `Connecting ${connectFrom.id()}: click the other router` : connecting ? "Click two routers to connect them" : cy.nodes().length ? "" : "Add a router to begin";
  }

  cy.on("zoom", () => cy.style().update());
  cy.on("dragfree", "node", (e) => {
    const n = e.target;
    if (mode === "map") n.data("location", projection.unproject(n.position()));
    else graphPositions[n.id()] = { ...n.position() };
    changed();
  });

  // Editing

  // Unsaved means: different from what was loaded or saved last, not
  // merely touched. Positions count to a hundredth.
  const state = () => JSON.stringify({ name: $("name").value.trim(), roles, routers: routers() },
    (k, v) => (typeof v === "number" ? Math.round(v * 100) / 100 : v));
  const editor = UI.editor({
    kind: "topologies", original, used: window.TOPOLOGY_USED, state,
    body: () => ({ source: data.source, roles, routers: routers() }),
    // A state of the undo: the routers, their sessions and places again.
    restore: (text) => {
      const t = JSON.parse(text);
      $("name").value = t.name;
      for (const k of Object.keys(roles)) delete roles[k];
      Object.assign(roles, structuredClone(t.roles));
      Object.assign(data, { roles, routers: structuredClone(t.routers) });
      for (const k of Object.keys(graphPositions)) delete graphPositions[k];
      for (const [n, r] of Object.entries(t.routers)) if (r.position) graphPositions[n] = { ...r.position };
      cy.elements().remove();
      cy.add(elements());
      if (mode === "map" && !located()) mode = "graph";
      cy.nodes().forEach((n) => n.position(mode === "map" ? projection.project(n.data("location")) : graphPositions[n.id()] || { x: 0, y: 0 }));
      changed();
    },
  });

  // The panel is drawn again only when nothing is selected: a field being
  // edited keeps its focus.
  function changed() {
    mark();
    editor.mark();
    if (!cy.$(":selected").length) renderPanel();
    renderModes();
  }

  $("add").onclick = () => {
    let i = 1;
    while (cy.getElementById(`router-${i}`).length) i++;
    const name = `router-${i}`;
    const ids = new Set(cy.nodes().map((n) => n.data("routerId")));
    let id = 1;
    while (ids.has(`10.0.${id >> 8}.${id & 255}`)) id++;
    // In the middle of the view, beside the routers already there.
    const center = { x: (-cy.pan().x + cy.width() / 2) / cy.zoom(), y: (-cy.pan().y + cy.height() / 2) / cy.zoom() };
    const gap = 60 / cy.zoom();
    const taken = () => cy.nodes().some((n) => Math.hypot(n.position().x - center.x, n.position().y - center.y) < gap / 2);
    for (let k = 0; taken() && k < 50; k++) center.x += gap;
    const node = cy.add({ group: "nodes", data: {
      id: name, asn: Math.max(64999, ...cy.nodes().map((n) => +n.data("asn"))) + 1, routerId: `10.0.${id >> 8}.${id & 255}`,
      location: mode === "map" ? projection.unproject(center) : null,
    }, position: center });
    graphPositions[name] = { ...center };
    cy.$(":selected").unselect();
    node.select();
    changed();
  };

  $("connect").onclick = () => {
    connecting = !connecting;
    connectFrom?.removeClass("from");
    connectFrom = null;
    renderModes();
  };

  cy.on("tap", "node", (e) => {
    if (!connecting) return;
    const n = e.target;
    if (!connectFrom) {
      connectFrom = n;
      n.addClass("from");
    } else if (connectFrom !== n) {
      const id = [connectFrom.id(), n.id()].sort().join("|");
      if (!cy.getElementById(id).length) {
        cy.add({ group: "edges", data: { id, source: connectFrom.id(), target: n.id(), prefSource: null, prefTarget: null, rel: null } });
        changed();
      }
      connectFrom.removeClass("from");
      connectFrom = null;
    }
    renderModes();
  });

  $("layout").onclick = () => {
    if (mode === "map") { Graph.fit(cy, 48, 1.5); return; }
    arrange();
    changed();
  };
  document.querySelectorAll("#modes button").forEach((b) => (b.onclick = () => setMode(b.dataset.mode)));

  function remove(elements) {
    elements.forEach((e) => {
      if (!e.isNode()) return;
      delete graphPositions[e.id()];
      for (const role in roles) roles[role] = roles[role].filter((m) => m !== e.id());
    });
    cy.remove(elements);
    changed();
  }

  // Delete removes the selection, unless typing, in a dialog or on a button.
  document.addEventListener("keydown", (e) => {
    if (!["Delete", "Backspace"].includes(e.key) || !cy.$(":selected").length) return;
    if (e.target.closest("input, textarea, select, button, [contenteditable]") || document.querySelector("dialog[open]")) return;
    remove(cy.$(":selected"));
  });

  function rename(node, name) {
    if (!NAME.test(name) || name === node.id() || cy.getElementById(name).length) return false;
    const copy = cy.add({ group: "nodes", data: { ...node.data(), id: name }, position: { ...node.position() }, classes: node.classes() });
    node.connectedEdges().forEach((e) => {
      const source = e.source() === node ? name : e.source().id();
      const target = e.target() === node ? name : e.target().id();
      cy.add({ group: "edges", data: { ...e.data(), id: [source, target].sort().join("|"), source, target } });
    });
    graphPositions[name] = graphPositions[node.id()];
    delete graphPositions[node.id()];
    for (const role in roles) roles[role] = roles[role].map((m) => (m === node.id() ? name : m));
    cy.remove(node);
    copy.select();
    return true;
  }

  // Side panel

  // A field that only accepts what its checks allow; rejected input is marked.
  function field(label, value, onChange, attrs = {}) {
    const wrap = el("label", "block space-y-1");
    wrap.append(el("span", "label", label));
    const input = el("input", "input py-1.5 font-mono");
    Object.assign(input, attrs, { value: value ?? "" });
    input.onchange = () => {
      const ok = input.checkValidity() && onChange(input.value.trim()) !== false;
      input.classList.toggle("border-rose-500", !ok);
    };
    wrap.append(input);
    return wrap;
  }

  function renderPanel() {
    const panel = $("panel");
    panel.replaceChildren();
    const selected = cy.$(":selected");
    if (selected.length === 1 && selected.isNode()) {
      const n = selected[0];
      panel.append(el("h2", "section-title", "Router"));
      panel.append(field("Name", n.id(), (v) => rename(n, v) && changed(), { pattern: NAME.source.slice(1, -1), required: true }));
      panel.append(field("ASN", n.data("asn"), (v) => { n.data("asn", +v); changed(); renderPanel(); }, { type: "number", min: 1, required: true }));
      // The network behind the ASN, for topologies imported from CAIDA.
      const known = (window.AS_NAMES || {})[n.data("asn")];
      if (known) {
        let country = known.country;
        try { country = new Intl.DisplayNames("en", { type: "region" }).of(known.country); } catch { /* not a region code */ }
        panel.append(el("p", "-mt-1 text-sm", [known.org || known.name, country].filter(Boolean).join(" · ")));
      }
      panel.append(field("Router ID", n.data("routerId"), (v) => { n.data("routerId", v); changed(); }, { required: true }));
      const loc = n.data("location");
      panel.append(el("p", "muted text-xs", [`${n.degree()} sessions`, loc && `${loc.lat}, ${loc.lon}`].filter(Boolean).join(" · ")));
      const chips = el("div", "flex flex-wrap gap-2");
      for (const role of Object.keys(roles)) {
        const chip = el("label", "chip");
        const box = el("input");
        Object.assign(box, { type: "checkbox", checked: roles[role].includes(n.id()) });
        box.onchange = () => {
          roles[role] = box.checked ? [...roles[role], n.id()] : roles[role].filter((m) => m !== n.id());
          if (role === "origins") n.toggleClass("origin", box.checked);
          changed();
        };
        chip.append(box, el("span", "", role === "origins" ? "Origin" : role));
        chips.append(chip);
      }
      const hybrid = el("label", "chip");
      hybrid.dataset.tip = "Runs OBGP in hybrid variants, BGP otherwise";
      const box = el("input");
      Object.assign(box, { type: "checkbox", checked: n.hasClass("obgp") });
      box.onchange = () => { n.toggleClass("obgp", box.checked); changed(); };
      hybrid.append(box, el("span", "", "OBGP in hybrids"));
      chips.append(hybrid);
      panel.append(chips);
      const del = el("button", "btn btn-danger w-full");
      del.innerHTML = `${UI.icon("delete")}Delete router`;
      del.onclick = () => remove(n);
      panel.append(del);
    } else if (selected.length === 1 && selected.isEdge()) {
      const e = selected[0];
      const a = e.source().id(), b = e.target().id();
      panel.append(el("h2", "section-title", "Session"));
      panel.append(el("p", "font-mono text-sm text-slate-600 dark:text-slate-300", `${a} ↔ ${b}`));
      // Without a value of its own, an end prefers by the relation of the other end.
      const byRelation = { customer: 200, peer: 150, provider: 100 };
      const fallback = (key) => byRelation[(key === "prefSource" ? OF_TARGET : OF_SOURCE)[e.data("rel")]] ?? 100;
      const prefs = [["prefSource", a], ["prefTarget", b]].map(([key, at]) => [key, field(`Local Preference at ${at}`, e.data(key),
        (v) => { e.data(key, v ? +v : null); changed(); }, { type: "number", min: 1, placeholder: fallback(key) })]);
      const relation = el("label", "block space-y-1");
      const select = el("select", "input py-1.5");
      for (const [value, text] of [["", "None"], ["p2c", `${a} provides ${b}`], ["c2p", `${b} provides ${a}`], ["p2p", "Peers"]]) {
        select.append(Object.assign(el("option", "", text), { value, selected: (e.data("rel") || "") === value }));
      }
      select.onchange = () => {
        e.data("rel", select.value || null);
        for (const [key, f] of prefs) f.querySelector("input").placeholder = fallback(key);
        changed();
      };
      relation.append(el("span", "label", "Relation"), select);
      panel.append(relation, ...prefs.map(([, f]) => f));
      panel.append(el("p", "muted text-xs", "Higher is preferred. Without a relation 100, else 200 from customers, 150 from peers, 100 from providers."));
      const del = el("button", "btn btn-danger w-full");
      del.innerHTML = `${UI.icon("delete")}Delete session`;
      del.onclick = () => remove(e);
      panel.append(del);
    } else {
      const prefs = cy.edges().reduce((s, e) => s + custom(e.data("prefSource")) + custom(e.data("prefTarget")), 0);
      const stats = el("dl", "grid grid-cols-3 gap-2");
      for (const [label, value] of [["Routers", cy.nodes().length], ["Sessions", cy.edges().length], ["Preferences", prefs]]) {
        const d = el("div");
        d.append(el("dt", "label", label), el("dd", "mt-0.5 text-lg font-medium tabular-nums", value));
        stats.append(d);
      }
      panel.append(stats);
      // OBGP in hybrids, for whole roles at once.
      const hybrid = el("div", "space-y-2 border-t border-slate-100 pt-4 dark:border-white/5");
      const marked = cy.nodes(".obgp").length;
      hybrid.append(el("div", "flex items-baseline justify-between", ""));
      hybrid.firstChild.append(el("h3", "label", "OBGP in hybrids"), el("span", "text-sm tabular-nums", `${marked} of ${cy.nodes().length}`));
      const groups = [["All routers", cy.nodes()], ...Object.entries(roles).filter(([, m]) => m.length).map(([role, members]) =>
        [role === "origins" ? "Origins" : role, cy.nodes().filter((n) => members.includes(n.id()))])];
      for (const [name, nodes] of groups) {
        const row = el("div", "flex items-center gap-2 text-sm");
        const set = (on) => { nodes.forEach((n) => n.toggleClass("obgp", on)); changed(); };
        const mark = el("button", "btn px-2 py-0.5 text-xs", "Mark"), clear = el("button", "btn px-2 py-0.5 text-xs", "Clear");
        Object.assign(mark, { type: "button", onclick: () => set(true) });
        Object.assign(clear, { type: "button", onclick: () => set(false) });
        row.append(el("span", "min-w-0 flex-1 truncate", `${name} (${nodes.length})`), mark, clear);
        hybrid.append(row);
      }
      panel.append(hybrid);
      const legend = el("ul", "muted space-y-2 border-t border-slate-100 pt-4 text-xs dark:border-white/5");
      const swatch = (style) => { const e = el("span", "inline-block shrink-0"); Object.assign(e.style, style); return e; };
      for (const [mark, text] of [
        [swatch({ width: "9px", height: "9px", background: "var(--graph-accent)", transform: "rotate(45deg)", margin: "0 4px" }), "Origin"],
        [swatch({ width: "10px", height: "10px", background: "var(--graph-node)", borderRadius: "3px", margin: "0 3px" }), "OBGP in hybrids"],
        [swatch({ width: "17px", height: "2px", background: "var(--graph-accent-soft)" }), "Local Preference, at the router that prefers"],
        [el("span", "w-[17px] text-center leading-none", "→"), "Provider to customer"],
        [el("span", "w-[17px] text-center leading-none", "•–•"), "Peers"],
      ]) { const li = el("li", "flex items-center gap-2"); li.append(mark, el("span", "", text)); legend.append(li); }
      panel.append(legend, el("p", "muted text-xs", "Select a router or session to edit it."));
    }
  }

  cy.on("select unselect", () => setTimeout(renderPanel));
  $("name").oninput = editor.mark;

  document.addEventListener("lab:theme", () => cy.style(style()));

  setMode(located() ? "map" : "graph");
  renderPanel();
})();
