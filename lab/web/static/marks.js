// The notes panel of the top bar, see partials/notes-panel.html: the notes of this page, or every note and star of
// the lab. It stays open from page to page until closed. Its forms post and get the panel back, the page stays.
// In a note Enter saves, Shift+Enter breaks the line, Escape cancels.
(() => {
  const drawer = document.getElementById("notes");
  const toggle = document.querySelector("[data-notes-toggle]");
  const badge = document.querySelector("[data-notes-badge]");
  if (!drawer || !toggle) return;
  const store = {
    get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private window: forgotten */ } },
  };
  const show = (html) => {
    drawer.innerHTML = html;
    const panel = drawer.querySelector(".notes-panel");
    if (!panel) return;
    store.set("notes-view", panel.dataset.view);
    const open = Number(panel.dataset.hereOpen) || 0;
    badge.hidden = !open;
    badge.textContent = open;
  };
  const load = async (view) => {
    const q = new URLSearchParams({ kind: drawer.dataset.kind, name: drawer.dataset.name, view: view || store.get("notes-view") || "" });
    show(await (await fetch(`/marks/panel?${q}`)).text());
  };
  const open = async (view) => {
    drawer.hidden = false;
    toggle.setAttribute("aria-expanded", "true");
    store.set("notes-open", "1");
    await load(view);
  };
  const close = () => {
    drawer.hidden = true;
    toggle.setAttribute("aria-expanded", "false");
    store.set("notes-open", "");
  };
  toggle.addEventListener("click", () => (drawer.hidden ? open() : close()));
  if (store.get("notes-open")) open();

  const editing = (note, on) => {
    note.querySelector(".note-edit").hidden = !on;
    note.classList.toggle("is-editing", on);
    if (on) note.querySelector(".note-edit textarea").focus();
  };
  drawer.addEventListener("click", (e) => {
    const view = e.target.closest("[data-notes-view]");
    if (view) return load(view.dataset.notesView);
    if (e.target.closest("[data-notes-close]")) return close();
    const edit = e.target.closest("[data-note-open], [data-note-cancel]");
    if (edit) return editing(edit.closest("[data-note]"), edit.hasAttribute("data-note-open"));
    const sure = e.target.closest("[data-two-step]");
    if (sure && !sure.dataset.armed) {  // a second click deletes, the first only asks
      e.preventDefault();
      sure.dataset.armed = "1";
      sure.dataset.label = sure.innerHTML;
      sure.textContent = sure.closest("[data-bulk]") ? deleting(sure.closest("[data-bulk]")) : sure.dataset.twoStep;
      sure.classList.add("btn-danger");
    }
  });

  // The overview: picked notes and objects, all of those shown at once, and the actions that fit them.
  const count = (n, one) => `${n} ${one}${n === 1 ? "" : "s"}`;
  const deleting = (form) => {
    const notes = form.querySelectorAll("[data-pick-note]:checked").length;
    const stars = form.querySelectorAll("[data-pick-object][data-starred]:checked").length;
    return `Remove ${[notes && count(notes, "note"), stars && count(stars, "star")].filter(Boolean).join(" and ")}? The pages stay.`;
  };
  const picked = (form) => {
    const boxes = [...form.querySelectorAll("[data-pick-note], [data-pick-object]")];
    const on = boxes.filter((b) => b.checked);
    const notes = on.filter((b) => b.hasAttribute("data-pick-note")).length;
    const stars = on.filter((b) => b.hasAttribute("data-starred")).length;
    const all = form.querySelector("[data-pick-all]");
    all.checked = on.length > 0 && on.length === boxes.length;
    all.indeterminate = on.length > 0 && on.length < boxes.length;
    form.querySelector("[data-picked-count]").textContent = on.length ? `${notes} note${notes === 1 ? "" : "s"}, ${stars} star${stars === 1 ? "" : "s"}` : "";
    form.querySelectorAll("[data-needs]").forEach((b) => {
      const done = on.filter((x) => x.hasAttribute("data-done")).length;
      b.hidden = !{ open: notes - done, done, star: stars, any: notes + stars }[b.dataset.needs];
      if (b.dataset.armed) { delete b.dataset.armed; b.classList.remove("btn-danger"); b.innerHTML = b.dataset.label || b.innerHTML; }
    });
  };
  drawer.addEventListener("change", (e) => {
    if (e.target.name === "color") {  // the slip takes the colour picked, as it will be saved
      const slip = e.target.closest(".note");
      slip.className = slip.className.replace(/\bnote-(yellow|pink|blue|violet|orange)\b/, `note-${e.target.value}`);
      return;
    }
    const form = e.target.closest("[data-bulk]");
    if (!form) return;
    if (e.target.matches("[data-pick-all]")) {
      form.querySelectorAll("[data-pick-note], [data-pick-object]").forEach((b) => (b.checked = e.target.checked));
    } else if (e.target.matches("[data-pick-object]")) {  // an object takes the notes shown under it along
      e.target.closest("[data-object]").querySelectorAll("[data-pick-note]").forEach((b) => (b.checked = e.target.checked));
    }
    picked(form);
  });
  drawer.addEventListener("submit", async (e) => {
    const form = e.target.closest("[data-panel-form]");
    if (!form) return;
    e.preventDefault();
    const to = form.getAttribute("action");  // form.action would be its button named action
    const sent = await fetch(to, { method: "POST", body: new FormData(form, e.submitter), headers: { "X-Notes-Panel": "1" } });
    show(await sent.text());
    // A star of this page taken away in the overview: the page shows it too.
    if (to.endsWith("/star") && form.elements.name?.value === drawer.dataset.name) location.reload();
  });
  drawer.addEventListener("keydown", (e) => {
    const text = e.target.closest("[data-note-text]");
    if (text && e.key === "Enter" && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      if (text.value.trim()) text.form.requestSubmit();
    } else if (e.key === "Escape") {
      e.stopPropagation();
      const note = e.target.closest("[data-note]");
      if (note && !note.querySelector(".note-edit").hidden) editing(note, false);
      else if (text && text.value) text.value = "";
      else { close(); toggle.focus(); }
    }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !drawer.hidden && !document.querySelector("dialog[open]")) close();
  });
})();
