// Groups of the main views (data-groups="<kind>" on the list): a heading
// folds its group, remembered per browser; dragging an item onto another
// group moves it there, onto the zone below the list into a new group,
// which asks for its name. A search opens the groups and hides those
// without a match.
(() => {
  const list = document.querySelector("[data-groups]");
  if (!list) return;
  const kind = list.dataset.groups, key = `lab:folded:${kind}`;
  const zone = document.querySelector("[data-group-new]");
  const groups = () => [...list.querySelectorAll("[data-group]")];
  const items = (g) => [...g.querySelectorAll("[data-item]")];
  const holder = (g) => (g.matches("tbody") ? g : g.querySelector("[data-group-items]"));

  // Folding
  let folded;
  try { folded = new Set(JSON.parse(localStorage.getItem(key)) || []); } catch { folded = new Set(); }
  const fold = (g, on) => {
    g.classList.toggle("folded", on);
    g.querySelector("[data-group-toggle]")?.setAttribute("aria-expanded", !on);
  };
  groups().forEach((g) => fold(g, folded.has(g.dataset.group)));
  list.addEventListener("click", (e) => {
    const toggle = e.target.closest("[data-group-toggle]");
    if (!toggle) return;
    const g = toggle.closest("[data-group]"), on = !g.classList.contains("folded");
    fold(g, on);
    on ? folded.add(g.dataset.group) : folded.delete(g.dataset.group);
    try { localStorage.setItem(key, JSON.stringify([...folded])); } catch {}
  });

  // Collapse all, or expand all once every group is folded
  const all = document.querySelector("[data-groups-all]");
  const label = () => {
    if (!all) return;
    const every = groups().every((g) => g.classList.contains("folded"));
    all.classList.toggle("folded", every);  // the chevron points right, as on a folded group
    all.dataset.tip = every ? "Expand all" : "Collapse all";
    all.setAttribute("aria-label", all.dataset.tip);
  };
  all?.addEventListener("click", () => {
    const on = !all.classList.contains("folded");
    groups().forEach((g) => { fold(g, on); on ? folded.add(g.dataset.group) : folded.delete(g.dataset.group); });
    try { localStorage.setItem(key, JSON.stringify([...folded])); } catch {}
    label();
  });
  list.addEventListener("click", (e) => e.target.closest("[data-group-toggle]") && label());
  label();

  // Renaming: a double click on the name of a group, Enter keeps it,
  // Escape not. A name that exists merges the two; the page shows the
  // groups anew, in their order.
  list.addEventListener("dblclick", (e) => {
    const shown = e.target.closest("[data-group-name]");
    if (!shown) return;
    const toggle = shown.closest("[data-group-toggle]"), g = toggle.closest("[data-group]"), old = g.dataset.group;
    fold(g, folded.has(old));  // the double click folded it twice
    const input = UI.el("input", "input group-rename py-1");
    input.value = old;
    input.setAttribute("aria-label", `New name of ${old}`);
    toggle.hidden = true;
    toggle.after(input);
    input.focus();
    input.select();
    const end = () => { input.remove(); toggle.hidden = false; };
    input.onkeydown = async (k) => {
      if (k.key === "Escape") return end();
      if (k.key !== "Enter") return;
      k.preventDefault();
      const name = input.value.trim();
      if (!name || name === old) return end();
      const form = new FormData();
      form.append("old", old);
      form.append("new", name);
      const { ok, data } = await UI.post(`/groups/${kind}/rename`, form);
      if (!ok) return alert(data?.problems?.[0] || "The group could not be renamed.");
      if (folded.delete(old)) folded.add(data.group);
      try { localStorage.setItem(key, JSON.stringify([...folded])); } catch {}
      location.reload();
    };
    input.onblur = end;
  });

  // Search: after ui.js has hidden the items without a match
  document.addEventListener("input", (e) => {
    if (!e.target.matches?.("input[data-filter]")) return;
    const searching = !!e.target.value.trim();
    list.classList.toggle("searching", searching);
    groups().forEach((g) => (g.hidden = searching && items(g).every((i) => i.hidden)));
    // "No matches" of ui.js goes into the first table body: give it one of its own.
    const none = list.querySelector("tr[data-no-matches]");
    if (none && !none.parentElement.matches("[data-none]")) {
      const body = Object.assign(document.createElement("tbody"), { hidden: false });
      body.dataset.none = "";
      list.append(body);
      body.append(none);
    }
  });

  // Moving
  const count = (g) => { g.querySelector("[data-group-count]").textContent = items(g).length; };
  const place = (g, item) => {
    const next = items(g).find((i) => i !== item && i.dataset.item > item.dataset.item);
    holder(g).insertBefore(item, next || null);
  };
  const create = (name) => {
    const g = document.querySelector("template[data-group-template]").content.firstElementChild.cloneNode(true);
    g.dataset.group = name;
    g.querySelector("[data-group-name]").textContent = name;
    const other = groups().find((x) => x.dataset.group === "Other");
    other ? other.before(g) : (zone && zone.parentElement === list ? zone.before(g) : list.append(g));
    sortable(holder(g));
    return g;
  };
  const move = async (item, name, from) => {
    const target = groups().find((x) => x.dataset.group === name);
    if (target) place(target, item);  // at its place at once, back if the lab refuses
    const form = new FormData();
    form.append("name", item.dataset.item);
    form.append("group", name);
    const { ok, data } = await UI.post(`/groups/${kind}`, form);
    if (!ok) {
      place(from, item);
      alert(data?.problems?.[0] || "The item could not be moved.");
      return;
    }
    const g = groups().find((x) => x.dataset.group === data.group) || create(data.group);
    if (g.classList.contains("folded")) fold(g, false), folded.delete(g.dataset.group);
    place(g, item);
    count(g);
    count(from);
    if (!items(from).length) from.remove();
    item.classList.add("moved");
    setTimeout(() => item.classList.remove("moved"), 1200);
  };

  // A new group: the zone asks for its name, Escape puts the item back.
  const ask = (item, from) => {
    const input = zone.querySelector("[data-new-name]");
    zone.classList.add("asking");
    item.hidden = true;
    input.value = "";
    input.focus();
    const done = (name) => {
      input.onkeydown = input.onblur = null;
      zone.classList.remove("asking");
      item.hidden = false;
      name ? move(item, name, from) : place(from, item);
    };
    input.onkeydown = (e) => {
      if (e.key === "Enter") { e.preventDefault(); done(input.value.trim()); }
      if (e.key === "Escape") done("");
    };
    input.onblur = () => done(input.value.trim());
  };

  const sortable = (element) => Sortable.create(element, {
    group: kind, sort: false, animation: 150, draggable: "[data-item]",
    onStart: () => (document.body.dataset.draggingItem = ""),
    onMove: (e) => {
      list.querySelectorAll(".drop-into").forEach((x) => x.classList.remove("drop-into"));
      (e.to.closest("[data-group]") || e.to.closest("[data-group-new]"))?.classList.add("drop-into");
    },
    onEnd: (e) => {
      delete document.body.dataset.draggingItem;
      document.querySelectorAll(".drop-into").forEach((x) => x.classList.remove("drop-into"));
      if (e.to === e.from) return;
      const from = e.from.closest("[data-group]");
      if (e.to.closest("[data-group-new]")) ask(e.item, from);
      else move(e.item, e.to.closest("[data-group]").dataset.group, from);
    },
  });
  addEventListener("DOMContentLoaded", () => {
    if (!window.Sortable) return;
    groups().forEach((g) => sortable(holder(g)));
    if (zone) sortable(holder(zone) || zone);
  });
})();
