// Helpers of the interface, on every page.
window.UI = {
  // Goes to another view of the same page, a topology or scenario, and keeps
  // where the page was scrolled to instead of jumping to the top.
  go(url) {
    try { sessionStorage.setItem("keep-scroll", JSON.stringify({ y: scrollY, at: Date.now() })); } catch { /* private window */ }
    location.href = url;
  },
  css: (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim(),

  el(tag, className, text) {
    const e = document.createElement(tag);
    if (className) e.className = className;
    if (text != null) e.textContent = text;
    return e;
  },

  // The sprite with the version the page names, see static() in app.py.
  icon: (name, cls = "") => `<svg class="icon ${cls}" aria-hidden="true"><use href="${UI.icons()}#${name}"/></svg>`,
  icons: () => document.documentElement.dataset.icons || "/static/icons.svg",

  // Posts JSON, or a FormData as a form; {ok, data}, with a problem to show
  // when the server did not answer with JSON, e.g. after the session expired.
  async post(url, body) {
    const form = body instanceof FormData;
    try {
      const response = await fetch(url, {
        method: "POST", body: form ? body : JSON.stringify(body),
        headers: form ? {} : { "Content-Type": "application/json" },
      });
      if (!response.headers.get("content-type")?.includes("json") || response.redirected) {
        return { ok: false, data: { problems: ["Sign in again."] } };
      }
      return { ok: response.ok, data: await response.json() };
    } catch {
      return { ok: false, data: { problems: ["The lab is not reachable."] } };
    }
  },

  // The saving of an editor, alike in every editor: Save and Ctrl+S post
  // body() to /<kind>/save, a new name asks whether to rename or to save a
  // copy, problems and "Saved" show next to the title, and leaving with
  // unsaved changes asks first. Unsaved means different from what was
  // loaded or saved last; a new thing is unsaved until it is saved.
  // Undo and redo step through the states the editor had, up to 100;
  // changes within a moment, as in typing, count as one. restore(state)
  // puts a state back. In a text field its own undo goes first.
  editor({ kind, original, used = [], state, body, saved: onSaved, restore }) {
    const $ = (id) => document.getElementById(id);
    let saved = original ? state() : "", saving = false, leaving = false;
    const dirty = () => state() !== saved;
    // Leaving asks only about changes: a new thing nobody touched is unsaved, but nothing is lost.
    const opened = state();
    const losing = () => !leaving && dirty() && state() !== opened;
    let history = [state()], at = 0, last = 0, restoring = false;
    function record() {
      const now = state();
      if (restoring || now === history[at]) return;
      const join = Date.now() - last < 500 && at > 0;
      history = history.slice(0, join ? at : at + 1).concat(now).slice(-100);
      at = history.length - 1;
      last = Date.now();
    }
    function go(step) {
      if (!restore || !history[at + step]) return;
      at += step;
      last = 0;
      restoring = true;
      try { restore(history[at]); } finally { restoring = false; }
      mark();
    }
    const mark = () => {
      record();
      $("dirty").hidden = !dirty();
      if ($("undo")) { $("undo").disabled = !restore || at === 0; $("redo").disabled = !restore || at === history.length - 1; }
    };
    if ($("undo")) { $("undo").onclick = () => go(-1); $("redo").onclick = () => go(1); }
    document.addEventListener("keydown", (e) => {
      if (!(e.ctrlKey || e.metaKey) || e.target.closest?.("input:not([type=checkbox]):not([type=radio]), textarea, [contenteditable]")) return;
      const key = e.key.toLowerCase();
      if (key === "z" || key === "y") { e.preventDefault(); go(key === "y" || e.shiftKey ? 1 : -1); }
    });
    async function save(extra = {}) {
      if (saving) return;
      saving = true;
      try {
        const name = $("name").value.trim();
        let mode = null;
        if (original && name !== original) {
          mode = await UI.askSaveAs(original, name, used);
          if (!mode) return;
        }
        const request = body(name);
        if (request instanceof FormData) {
          for (const [k, v] of Object.entries({ name, original, mode: mode || "", ...extra })) request.set(k, v);
        } else Object.assign(request, { name, original, mode, ...extra });
        const { ok, data } = await UI.post(`/${kind}/save`, request);
        if (!ok) return UI.flash($("message"), false, (data.problems || ["Not saved."]).join(" "));
        saved = state();
        mark();
        if (onSaved?.(data)) return;
        UI.flash($("message"), true, "Saved");
        if (data.saved !== original) { leaving = true; location.href = `/${kind}/${data.saved}`; }
      } finally {
        saving = false;
      }
    }
    $("save").onclick = (e) => { e.preventDefault(); save(); };
    document.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "s") { e.preventDefault(); save(); } });
    document.addEventListener("lab:leave", () => { leaving = true; });  // e.g. deleted
    // The browser asks on its own only when the tab closes or reloads; a
    // link of the lab asks here, with saving as a choice.
    document.addEventListener("click", (e) => {
      const link = e.target.closest?.("a[href]");
      if (!link || !losing() || e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || link.target === "_blank") return;
      const url = new URL(link.href, location.href);
      if (url.origin !== location.origin || (url.pathname === location.pathname && url.search === location.search)) return;
      e.preventDefault();
      const dialog = $("leave");
      dialog.querySelectorAll("button").forEach((b) => (b.onclick = async () => {
        dialog.close();
        if (b.value === "cancel") return;
        if (b.value === "save") {
          await save();
          if (dirty()) return;  // not saved: the problems show next to the title
        }
        leaving = true;
        location.href = url.href;
      }));
      dialog.showModal();
    });
    UI.guardUnsaved(losing);
    mark();
    return { mark, dirty, save, leave: () => { leaving = true; } };
  },

  // A short message next to a Save button.
  flash(element, ok, text) {
    element.className = ok ? "text-sm text-emerald-700 dark:text-emerald-400" : "error";
    element.textContent = text;
    if (ok) setTimeout(() => { if (element.textContent === text) element.textContent = ""; }, 2000);
  },

  // Warns before leaving a page with unsaved changes.
  guardUnsaved(unsaved) {
    addEventListener("beforeunload", (e) => { if (unsaved()) e.preventDefault(); });
  },

  // Asks what to do when a thing is saved under a new name: "rename",
  // "copy" or null. A thing in use can only be copied.
  askSaveAs(oldName, newName, usedBy) {
    const dialog = document.getElementById("save-as");
    dialog.querySelector("[data-new-name]").textContent = newName;
    dialog.querySelector("[data-old-name]").textContent = oldName;
    dialog.querySelector("[data-used]").textContent = usedBy?.length ? `is used by ${usedBy.join(", ")}, so it stays.` : "can be renamed or kept.";
    dialog.querySelector("[data-rename]").hidden = !!usedBy?.length;
    return new Promise((resolve) => {
      dialog.querySelectorAll("button").forEach((b) => (b.onclick = () => { dialog.close(); resolve(b.value === "cancel" ? null : b.value); }));
      dialog.onclose = () => resolve(null);
      dialog.showModal();
    });
  },
};

// Custom controls. A <select> becomes a button with a listbox; an input
// with a <datalist> gets a list of suggestions. The native elements stay
// in the page, hidden, so forms and htmx keep working, and they receive
// the usual input and change events. New elements are enhanced as they
// appear, on a touch screen too, so that every menu of the lab looks alike.
(() => {
  let open = null;  // the open popover: {panel, close, key}
  let ids = 0;

  function popover(anchor, items, { current, onPick, filter = "" }) {
    open?.close();
    const shown = items.filter((i) => !filter || i.label.toLowerCase().includes(filter.toLowerCase()));
    if (!shown.length) return;
    const panel = UI.el("div", "popover");
    panel.id = `listbox-${++ids}`;
    panel.setAttribute("role", "listbox");
    let active = Math.max(0, shown.findIndex((i) => i.value === current));
    const options = shown.map((item, n) => {
      const b = UI.el("button", "option");
      b.type = "button";
      b.id = `${panel.id}-${n}`;
      b.tabIndex = -1;
      b.setAttribute("role", "option");
      b.setAttribute("aria-selected", item.value === current);
      b.append(UI.el("span", `truncate ${item.cls || ""}`, item.label));  // an option's own colour, e.g. a mode with a problem
      if (item.value === current) b.insertAdjacentHTML("beforeend", UI.icon("check"));
      b.onmousedown = (e) => e.preventDefault();  // keeps the focus on the anchor
      b.onclick = () => { onPick(item.value); close(); };
      b.onmouseenter = () => focus(n, false);
      panel.append(b);
      return b;
    });
    function focus(n, scroll = true) {
      active = (n + options.length) % options.length;
      options.forEach((b, i) => b.classList.toggle("active", i === active));
      anchor.setAttribute("aria-activedescendant", options[active].id);
      if (scroll) options[active].scrollIntoView({ block: "nearest" });
    }
    function place() {
      const r = anchor.getBoundingClientRect();
      panel.style.minWidth = `${r.width}px`;
      panel.style.left = `${Math.min(r.left, innerWidth - panel.offsetWidth - 8)}px`;
      const below = innerHeight - r.bottom > Math.min(panel.offsetHeight, 260) + 8;
      panel.style.top = below ? `${r.bottom + 4}px` : `${Math.max(8, r.top - panel.offsetHeight - 4)}px`;
    }
    function close() {
      panel.remove();
      removeEventListener("scroll", place, true);
      removeEventListener("resize", place);
      if (open?.panel === panel) open = null;
      anchor.setAttribute("aria-expanded", "false");
      anchor.removeAttribute("aria-activedescendant");
    }
    (anchor.closest("dialog[open]") || document.body).append(panel);  // above a modal dialog, in it
    anchor.setAttribute("aria-controls", panel.id);
    place();
    focus(active);
    addEventListener("scroll", place, true);
    addEventListener("resize", place);
    anchor.setAttribute("aria-expanded", "true");
    open = {
      panel, close,
      key(e) {
        if (e.key === "ArrowDown") { focus(active + 1); e.preventDefault(); }
        else if (e.key === "ArrowUp") { focus(active - 1); e.preventDefault(); }
        else if (e.key === "Enter") { options[active].click(); e.preventDefault(); }
        else if (e.key === "Escape" || e.key === "Tab") close();
        else if (e.key.length === 1 && anchor.tagName === "BUTTON") {
          const n = shown.findIndex((i) => i.label.toLowerCase().startsWith(e.key.toLowerCase()));
          if (n >= 0) focus(n);
        }
      },
    };
  }

  document.addEventListener("mousedown", (e) => { if (open && !open.panel.contains(e.target) && !e.target.closest("[aria-expanded=true]")) open.close(); });

  const fire = (el) => ["input", "change"].forEach((t) => el.dispatchEvent(new Event(t, { bubbles: true })));

  function enhanceSelect(select) {
    select.dataset.custom = "1";
    const button = UI.el("button", `${select.className} select-button`);
    button.type = "button";
    button.setAttribute("aria-haspopup", "listbox");
    if (select.getAttribute("aria-label")) button.setAttribute("aria-label", select.getAttribute("aria-label"));
    const items = () => [...select.options].map((o) => ({ value: o.value, label: o.textContent.trim(), cls: o.className }));
    const label = () => {
      button.className = `${select.className} select-button`;  // a class the page sets on the select, e.g. a colour
      button.replaceChildren(UI.el("span", "truncate", select.selectedOptions[0]?.textContent.trim() ?? ""));
      button.insertAdjacentHTML("beforeend", UI.icon("chevron-down"));
    };
    const show = () => popover(button, items(), { current: select.value, onPick: (v) => { if (v !== select.value) { select.value = v; label(); fire(select); } } });
    button.onclick = () => (open ? open.close() : show());
    button.onkeydown = (e) => {
      if (open) open.key(e);
      else if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) { e.preventDefault(); show(); }
    };
    select.addEventListener("change", label);
    new MutationObserver(label).observe(select, { childList: true, subtree: true, attributes: true });
    select.hidden = true;
    select.after(button);
    label();
  }

  function enhanceSuggestions(input) {
    input.dataset.custom = "1";
    const list = input.getAttribute("list");
    input.removeAttribute("list");  // no native suggestions
    input.setAttribute("autocomplete", "off");
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    const items = () => [...(document.getElementById(list)?.options || [])].map((o) => ({ value: o.value, label: o.value }));
    const show = (filter) => popover(input, items(), { current: input.value, filter, onPick: (v) => { input.value = v; fire(input); } });
    input.addEventListener("focus", () => show(""));
    input.addEventListener("input", (e) => { if (e.isTrusted) show(input.value); });
    input.addEventListener("keydown", (e) => { if (open) open.key(e); else if (e.key === "ArrowDown") show(""); });
    input.addEventListener("blur", () => {
      const mine = open;
      setTimeout(() => { if (open === mine) mine?.close(); }, 100);
    });
  }

  function enhance(root) {
    root.querySelectorAll?.("select:not([data-custom]):not([multiple])").forEach(enhanceSelect);
    root.querySelectorAll?.("input[list]:not([data-custom])").forEach(enhanceSuggestions);
  }
  addEventListener("DOMContentLoaded", () => {
    enhance(document);
    new MutationObserver((records) => records.forEach((r) => r.addedNodes.forEach((n) => n.nodeType === 1 && enhance(n.parentNode || n))))
      .observe(document.body, { childList: true, subtree: true });
  });
})();

// A sheet: a dialog with a title and content, from the bottom edge on a
// phone (styles.css). It goes when closed, by its button, Escape or a tap beside it.
UI.sheet = (title, ...content) => {
  const dialog = UI.el("dialog", "dialog outline-none");
  dialog.tabIndex = -1;  // the focus goes to the sheet, not to its first button
  const head = UI.el("div", "flex items-center justify-between gap-3 px-5 pt-4 pb-2");
  const close = UI.el("button", "btn btn-icon border-transparent shadow-none");
  close.type = "button";
  close.setAttribute("aria-label", "Close");
  close.innerHTML = UI.icon("close");
  close.onclick = () => dialog.close();
  head.append(UI.el("h2", "min-w-0 truncate font-mono font-semibold", title), close);
  const body = UI.el("div", "max-h-[70vh] overflow-y-auto px-5 pb-4");
  body.append(...content);
  dialog.append(head, body);
  dialog.onclick = (e) => { if (e.target === dialog) dialog.close(); };
  dialog.onclose = () => dialog.remove();
  document.body.append(dialog);
  dialog.showModal();
  dialog.focus();
  return dialog;
};

// The runs of a cell (td[data-runs]), on a touch screen: a tap lists them
// in a sheet, each with its state, what it tells and its replay, which a
// tip cannot show without hover. Elsewhere a dot opens its replay at once.
document.addEventListener("click", (e) => {
  const cell = e.target.closest?.("td[data-runs]");
  if (!cell || !matchMedia("(pointer: coarse)").matches) return;
  e.preventDefault();
  const list = UI.el("ul", "divide-y divide-slate-100 dark:divide-white/5");
  [...cell.firstElementChild.children].forEach((run, i) => {
    const dot = run.matches("[role=img]") ? run : run.querySelector("[role=img]");
    const [first, ...facts] = (run.dataset.tip || `Run ${i + 1}: ${dot.getAttribute("aria-label")}`).split("\n");
    const li = UI.el("li", "flex items-start gap-3 py-3");
    const mark = UI.el("span", "mt-1.5 flex shrink-0");
    mark.append(dot.cloneNode());
    const text = UI.el("div", "min-w-0 flex-1");
    text.append(UI.el("p", "text-sm font-medium", first), ...facts.map((f) => UI.el("p", "muted mt-0.5 text-xs", f)));
    li.append(mark, text);
    if (run.href) {
      const replay = UI.el("a", "btn shrink-0", "Replay");
      replay.href = run.href;
      li.append(replay);
    }
    list.append(li);
  });
  UI.sheet(cell.dataset.runs, list);
});

// Search: an input with data-filter="<selector>" hides the elements with
// data-search inside the target that do not contain the text.
// When nothing matches, the list says so.
document.addEventListener("input", (e) => {
  const input = e.target.closest?.("input[data-filter]");
  if (!input) return;
  const q = input.value.trim().toLowerCase();
  const items = [...document.querySelectorAll(`${input.dataset.filter} [data-search]`)];
  items.forEach((el) => (el.hidden = !el.dataset.search.toLowerCase().includes(q)));
  const list = document.querySelector(input.dataset.filter);
  let none = list?.querySelector("[data-no-matches]");
  if (!none && list && items.length) {
    const table = list.querySelector("tbody");
    none = table ? UI.el("tr", "empty") : UI.el("p", "muted col-span-full py-10 text-center text-sm", "No matches.");
    if (table) none.append(Object.assign(UI.el("td", "", "No matches."), { colSpan: 99 }));
    none.dataset.noMatches = "";
    (table || list).append(none);
  }
  if (none) none.hidden = !items.length || items.some((el) => !el.hidden);
});
document.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.closest?.("input[data-filter]")) e.preventDefault(); });

// What an agent asks for: a card on every page but the settings, which list all. "Later" hides it
// until an agent asks for something new.
(() => {
  const key = "asks-later";
  const later = () => { try { return new Set(JSON.parse(localStorage.getItem(key) || "[]")); } catch { return new Set(); } };
  const show = () => {
    const card = document.querySelector("[data-asks]");
    if (!card) return;
    const ids = card.dataset.asks.split(",");
    card.hidden = location.pathname.startsWith("/settings") || ids.every((id) => later().has(id));
  };
  document.addEventListener("click", (e) => {
    const card = e.target.closest?.("[data-ask-later]")?.closest("[data-asks]");
    if (!card) return;
    try { localStorage.setItem(key, JSON.stringify(card.dataset.asks.split(","))); } catch { /* private window: it shows again */ }
    card.hidden = true;
  });
  document.addEventListener("DOMContentLoaded", show);
  document.addEventListener("htmx:afterSwap", show);
})();

// Copy: a button with data-copy="#id" copies the text of that element.
document.addEventListener("click", async (e) => {
  const button = e.target.closest?.("button[data-copy]");
  const source = button && document.querySelector(button.dataset.copy);
  if (!source) return;
  try {
    await navigator.clipboard.writeText(source.textContent.trim());
    button.textContent = "Copied";
  } catch {
    getSelection().selectAllChildren(source);  // no clipboard without HTTPS: selected to copy by hand
  }
});

// Confirmation: a button with data-confirm="Question?" asks first, in a
// dialog of the lab, then posts to its data-action, or else to the action
// of its form. Its answer is red, unless data-confirm-safe says that
// nothing is lost, e.g. for starting a run. The target is taken when asked, because htmx may have
// replaced the button meanwhile.
document.addEventListener("click", (e) => {
  const button = e.target.closest?.("button[data-confirm]");
  if (!button) return;
  e.preventDefault();
  const action = button.dataset.action || button.form.action;
  const dialog = document.getElementById("confirm");
  dialog.querySelector("[data-title]").textContent = button.dataset.confirm;
  dialog.querySelector("[data-text]").textContent = button.dataset.confirmText || "";
  const ok = dialog.querySelector("[data-ok]");
  ok.textContent = button.getAttribute("aria-label") || button.textContent.trim();
  ok.className = `btn ${button.hasAttribute("data-confirm-safe") ? "btn-primary" : "btn-danger"}`;
  dialog.querySelectorAll("button").forEach((b) => (b.onclick = () => {
    dialog.close();
    if (b.value !== "yes") return;
    document.dispatchEvent(new CustomEvent("lab:leave"));  // the page goes, saved or not
    const form = Object.assign(document.createElement("form"), { method: "post", action });
    document.body.append(form);
    form.submit();
  }));
  dialog.showModal();
}, true);

// Tooltips: one element for every [data-tip], below it or above it when
// there is no room, kept inside the window.
(() => {
  let tip = null, timer = null, target = null, spot = null;
  const hide = () => { clearTimeout(timer); tip?.remove(); tip = null; target = null; };
  // A tip is one line of text, or a heading over lines, where "Key: value"
  // lines line up as a table. An element may build its own (el.tip, a function).
  function lines(text) {
    const all = text.split("\n"), out = [];
    const pair = (line) => line.match(/^([^:]{1,28}): (.+)$/);
    all.forEach((line, i) => {
      const kv = all.length > 1 && pair(line);
      if (!kv) out.push(UI.el("div", all.length > 1 && i === 0 ? "tip-head" : all.length > 1 ? "tip-row" : "", line));
      else {
        if (!out.at(-1)?.classList.contains("tip-pairs")) out.push(UI.el("dl", "tip-pairs"));
        out.at(-1).append(UI.el("dt", "", kv[1]), UI.el("dd", "", kv[2]));
      }
    });
    return out;
  }
  function fill(el) {
    if (el.tip) tip.replaceChildren(el.tip());
    else tip.replaceChildren(...lines(el.dataset.tip));
    const r = el.getBoundingClientRect(), w = tip.offsetWidth, h = tip.offsetHeight;
    const left = el.dataset.tipAlign === "end" ? r.right - w : r.left + r.width / 2 - w / 2;
    tip.style.left = `${Math.max(8, Math.min(left, innerWidth - w - 8))}px`;
    tip.style.top = `${r.bottom + 6 + h > innerHeight ? r.top - h - 6 : r.bottom + 6}px`;
    spot = [r.left + r.width / 2, r.top + r.height / 2];
  }
  function show(el) {
    if (!el.isConnected) return;  // replaced meanwhile, e.g. by a refresh
    tip = UI.el("div", "tooltip");
    tip.setAttribute("role", "tooltip");
    // An open modal dialog lies above the page: a tip of it belongs into it.
    (el.closest("dialog[open]") || document.body).append(tip);
    fill(el);
  }
  function over(e) {
    if (e.pointerType === "touch") return;  // no hover on touch, see the tap below
    const el = e.target.closest?.("[data-tip]");
    if (el === target) return;
    hide();
    if (!el || !el.dataset.tip) return;
    target = el;
    timer = setTimeout(() => show(el), e.type === "focusin" ? 0 : 350);
  }
  document.addEventListener("pointerover", over);
  // A refresh replaces the element of an open tip: the tip stays and moves
  // to the element now at its place, under the pointer or, on touch, where
  // the old one was. Only its text and place change, so that it does not flicker.
  let pointer = null;
  document.addEventListener("pointermove", (e) => { if (e.pointerType !== "touch") pointer = [e.clientX, e.clientY]; }, { passive: true });
  document.addEventListener("htmx:afterSwap", () => {
    if (!target || target.isConnected) return;
    const at = pointer || spot;
    const el = at && document.elementFromPoint(...at)?.closest("[data-tip]");
    if (!el?.dataset.tip) return hide();
    target = el;
    if (tip) fill(el);
    else { clearTimeout(timer); timer = setTimeout(() => show(el), 350); }
  });
  document.addEventListener("focusin", (e) => { if (e.target.matches?.(":focus-visible")) over(e); });
  document.addEventListener("pointerout", (e) => { if (target && !target.contains(e.relatedTarget)) hide(); });
  document.addEventListener("focusout", hide);
  // On touch a tap shows the tip of an element that does nothing else, the next tap hides it.
  let tapped = null, touch = false;
  document.addEventListener("pointerdown", (e) => { touch = e.pointerType === "touch"; tapped = tip ? target : null; hide(); });
  document.addEventListener("click", (e) => {
    const el = e.target.closest?.("[data-tip]");
    if (!touch || !el?.dataset.tip || el === tapped) return;
    if (e.target.closest("a, button, input, select, textarea, label, summary, [data-runs]")) return;
    target = el;
    show(el);
  });
  addEventListener("scroll", hide, true);
})();

// The dock: the queue opens and closes with its button, and stays so
// while the dock refreshes. Its entries are dragged by their handle, or
// moved with the arrow keys on it; the dock does not refresh meanwhile.
document.addEventListener("click", (e) => {
  if (!e.target.closest?.("[data-dock-toggle]")) return;
  document.body.toggleAttribute("data-queue-open");
  syncDock();
});
// A menu (details[data-menu]) closes on a click elsewhere or on Escape.
document.addEventListener("click", (e) => {
  document.querySelectorAll("details[data-menu][open]").forEach((menu) => { if (!menu.contains(e.target)) menu.open = false; });
});
document.addEventListener("keydown", (e) => {
  const menu = e.key === "Escape" && e.target.closest?.("details[data-menu][open]");
  if (menu) { menu.open = false; menu.querySelector("summary").focus(); }
});
// The charts of the host open and close on a phone; the body keeps the
// state, since the card is replaced every few seconds.
const syncHost = () => document.querySelectorAll("[data-host-toggle]").forEach((b) => b.setAttribute("aria-expanded", document.body.hasAttribute("data-host-open")));
document.addEventListener("click", (e) => {
  if (!e.target.closest?.("[data-host-toggle]")) return;
  document.body.toggleAttribute("data-host-open");
  syncHost();
});
document.addEventListener("htmx:afterSwap", syncHost);
// A list of choices on a phone (.picker): the chosen ones, all of them on Choose.
document.addEventListener("click", (e) => {
  const button = e.target.closest?.("[data-pick-toggle]");
  if (!button) return;
  const picker = button.closest(".picker"), picking = picker.classList.toggle("picking");
  button.textContent = picking ? "Done" : "Choose";
  button.setAttribute("aria-expanded", picking);
  if (!picking) picker.scrollIntoView({ block: "nearest" });
});
// The stop menu of the dock closes on a click elsewhere.
document.addEventListener("click", (e) => {
  document.querySelectorAll("[data-dock-menu][open]").forEach((menu) => { if (!menu.contains(e.target)) menu.open = false; });
});
// A job shows its sub-jobs when opened; the running one is open unless closed.
const flipped = new Set();
document.addEventListener("click", (e) => {
  const job = e.target.closest?.("[data-job-toggle]")?.closest("[data-job]");
  if (!job) return;
  flipped.has(job.dataset.job) ? flipped.delete(job.dataset.job) : flipped.add(job.dataset.job);
  syncDock();
});
// The dock refreshes unless someone works in its queue right now: drags,
// has a menu open, or moved the pointer or pressed a key there within the
// last seconds. A pointer that rests there, or a focus a tap left behind on
// a touch screen, does not hold it still.
let dockTouched = 0;
for (const type of ["pointermove", "pointerdown", "keydown"]) {
  document.addEventListener(type, (e) => { if (e.target.closest?.("#dock-queue")) dockTouched = Date.now(); }, { passive: true });
}
UI.dockBusy = () => !!document.body.dataset.dragging || !!document.querySelector("#dock details[open], dialog[open]") || Date.now() - dockTouched < 5000;

function syncDock() {
  const open = document.body.hasAttribute("data-queue-open");
  document.querySelectorAll("[data-dock-toggle]").forEach((b) => b.setAttribute("aria-expanded", open));
  document.querySelectorAll("[data-job]").forEach((job) => {
    const shown = job.hasAttribute("data-open-default") !== flipped.has(job.dataset.job);
    job.classList.toggle("open", shown);
    job.querySelector("[data-job-toggle]")?.setAttribute("aria-expanded", shown);
  });
  const list = document.querySelector("[data-queue]");
  if (!list || list.sortable || !window.Sortable) return;
  list.sortable = Sortable.create(list, {
    // No dragging on a touch screen, where it fights with scrolling: the handle opens moves (below).
    disabled: matchMedia("(pointer: coarse)").matches,
    handle: ".drag-handle", animation: 150,
    onStart: () => (document.body.dataset.dragging = "1"),
    onEnd: () => { delete document.body.dataset.dragging; saveQueue(list); },
  });
}
async function saveQueue(list, focus) {
  const order = [...list.children].map((li) => li.dataset.name);
  await UI.post("/queue", { order });
  await htmx.ajax("GET", "/partials/dock", { target: "#dock", swap: "innerHTML" });
  if (focus) document.querySelector(`[data-queue] [data-name="${CSS.escape(focus)}"] .drag-handle`)?.focus();
}
// On a touch screen the handle of a waiting result offers its moves in a sheet.
document.addEventListener("click", (e) => {
  const handle = e.target.closest?.("[data-queue] .drag-handle");
  if (!handle || !matchMedia("(pointer: coarse)").matches) return;
  const name = handle.closest("li").dataset.name;
  const at = () => document.querySelector(`[data-queue] [data-name="${CSS.escape(name)}"]`);  // the dock refreshes meanwhile
  const choices = UI.el("div", "flex flex-col gap-1");
  for (const [label, where] of [["To the top", "top"], ["Move up", "up"], ["Move down", "down"]]) {
    const li = at(), other = where === "down" ? li.nextElementSibling : li.previousElementSibling;
    if (!other) continue;
    const b = UI.el("button", "dock-menu-item", label);
    b.type = "button";
    b.onclick = () => {
      sheet.close();
      const li = at(), list = li.parentElement;
      if (where === "top") list.prepend(li);
      else if (where === "up") li.previousElementSibling?.before(li);
      else li.nextElementSibling?.after(li);
      saveQueue(list);
    };
    choices.append(b);
  }
  if (!choices.children.length) choices.append(UI.el("p", "muted text-sm", "Nothing else waits."));
  const sheet = UI.sheet(name, choices);
});
document.addEventListener("keydown", (e) => {
  const handle = e.target.closest?.("[data-queue] .drag-handle");
  if (!handle || !["ArrowUp", "ArrowDown"].includes(e.key)) return;
  e.preventDefault();
  const li = handle.closest("li"), other = e.key === "ArrowUp" ? li.previousElementSibling : li.nextElementSibling;
  if (!other) return;
  e.key === "ArrowUp" ? other.before(li) : other.after(li);
  saveQueue(li.parentElement, li.dataset.name);
});
// Live parts refresh every few seconds. What comes back as it was is not
// replaced, so that hover, selection and open tips stay. Registered before
// every other swap handler, which then see shouldSwap.
(() => {
  const last = new Map();  // the path of a refresh -> what it gave last
  document.addEventListener("htmx:beforeSwap", (e) => {
    const { requestConfig, serverResponse, xhr } = e.detail;
    if (requestConfig?.verb !== "get" || xhr?.status !== 200) return;
    if (last.get(requestConfig.path) === serverResponse) e.detail.shouldSwap = false;
    else last.set(requestConfig.path, serverResponse);
  });
  // The element with focus has it again after a refresh, found by its id.
  let focused = null;
  document.addEventListener("htmx:beforeSwap", (e) => {
    const active = document.activeElement;
    focused = e.detail.shouldSwap && active?.id && e.detail.target.contains(active) ? active.id : null;
  });
  document.addEventListener("htmx:afterSwap", () => {
    if (focused) document.getElementById(focused)?.focus({ preventScroll: true });
    focused = null;
  });
})();
document.addEventListener("htmx:afterSwap", syncDock);
// The list is replaced by every refresh; its Sortable goes with it.
document.addEventListener("htmx:beforeSwap", (e) => {
  if (e.detail.shouldSwap && e.detail.target?.id === "dock") e.detail.target.querySelector("[data-queue]")?.sortable?.destroy();
});
addEventListener("load", syncDock);

// The theme button switches between light and dark; the choice stays
// with the browser. It shows what a click turns to.
(() => {
  function show() {
    const button = document.getElementById("theme");
    if (!button) return;
    const to = Theme.current() === "dark" ? "light" : "dark";
    button.dataset.tip = to === "dark" ? "Switch to dark" : "Switch to light";
    button.setAttribute("aria-label", button.dataset.tip);
    button.querySelector("use").setAttribute("href", `${UI.icons()}#theme-${to}`);
  }
  document.addEventListener("click", (e) => { if (e.target.closest?.("#theme")) Theme.toggle(); });
  document.addEventListener("lab:theme", show);
  addEventListener("DOMContentLoaded", show);
})();

// Scrolling: a box with data-keep-scroll="<key>" keeps where it was scrolled
// when htmx replaces it, e.g. on a refresh every few seconds. One that was
// at its end stays there, so that new lines show; with data-stick-bottom it
// starts at its end.
(() => {
  const kept = {};
  const atEnd = (el) => el.scrollHeight - el.scrollTop - el.clientHeight < 8;
  const toEnd = (root) => root.querySelectorAll?.("[data-stick-bottom]").forEach((el) => {
    if (!(el.dataset.keepScroll in kept)) el.scrollTop = el.scrollHeight;
  });
  document.addEventListener("htmx:beforeSwap", (e) => {
    if (!e.detail.shouldSwap) return;
    e.detail.target.querySelectorAll("[data-keep-scroll]").forEach((el) => {
      kept[el.dataset.keepScroll] = { top: el.scrollTop, left: el.scrollLeft, end: atEnd(el) };
    });
  });
  document.addEventListener("htmx:afterSwap", (e) => {
    e.detail.target.querySelectorAll("[data-keep-scroll]").forEach((el) => {
      const was = kept[el.dataset.keepScroll];
      if (!was) return;
      el.scrollLeft = was.left;
      el.scrollTop = was.end && "stickBottom" in el.dataset ? el.scrollHeight : was.top;
    });
    toEnd(e.detail.target);
  });
  addEventListener("DOMContentLoaded", () => toEnd(document));
})();

// The intro of a browser session: seen once, gone when it ends or on a click or key.
document.addEventListener("DOMContentLoaded", () => {
  const intro = document.getElementById("intro");
  if (!document.documentElement.classList.contains("intro")) { intro?.remove(); return; }
  try { sessionStorage.setItem("intro", "seen"); } catch { /* private window: it may show again */ }
  const end = () => { document.documentElement.classList.remove("intro"); intro?.remove(); };
  intro.addEventListener("animationend", (e) => { if (e.target === intro) end(); });
  intro.addEventListener("click", end);
  addEventListener("keydown", end, { once: true });
  setTimeout(end, 3500);  // in case no animation ends
});

// The scroll position UI.go kept, again once the page and its charts have laid out.
(() => {
  let kept = null;
  try { kept = JSON.parse(sessionStorage.getItem("keep-scroll")); sessionStorage.removeItem("keep-scroll"); } catch { /* private window */ }
  if (!kept || Date.now() - kept.at > 10000) return;
  const restore = () => scrollTo(0, kept.y);
  addEventListener("DOMContentLoaded", restore);
  addEventListener("load", () => { restore(); setTimeout(restore, 300); });
})();

// Times of day in the reader's time zone: the server writes its own, with
// the moment in datetime. Today shows the time, another day its weekday too.
(() => {
  const local = () => {
    const today = new Date().toDateString();
    for (const t of document.querySelectorAll("time[data-clock]")) {
      const when = new Date(t.getAttribute("datetime"));
      if (Number.isNaN(when.getTime())) continue;
      const hm = when.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
      t.textContent = when.toDateString() === today ? hm : `${when.toLocaleDateString("en-GB", { weekday: "short" })} ${hm}`;
    }
  };
  addEventListener("DOMContentLoaded", local);
  document.addEventListener("htmx:afterSwap", local);
})();
