"""Screenshots of every page and tab, see screens.sh. On the phone it also
checks what the guidelines for touch ask: no sideways scrolling, targets of
at least 24 px (WCAG 2.2) and 44 px (Apple) outside dense grids, fields and
selects of at least 36 px, which cannot have an invisible target around them,
and no text below 12 px. iOS zooms into fields below 16 px, base.html stops it."""

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[2]
RESULT, TOPOLOGY, SCENARIO, EXPERIMENT = "ifip-networking-2026", "noble-eu", "fill-60", "behaviour-oscillation"
PAGES = ["/experiments", f"/experiments/{EXPERIMENT}", "/experiments/new", "/topologies", f"/topologies/{TOPOLOGY}",
         "/topologies/new", "/scenarios", f"/scenarios/{SCENARIO}", "/scenarios/new", "/results", "/settings", "/simulation"]
PAGES += [f"/results/{RESULT}?tab={tab}" for tab in ("runs", "table", "charts", "replay", "quality", "details")]
SIZES = {"phone": (390, 844), "desktop": (1280, 900)}
PASSWORD = "screens-password"
# What breaks the guidelines on the page, visible elements only; links inside running text are exempt.
AUDIT = """() => {
  const seen = (e) => { const r = e.getBoundingClientRect(), s = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none"; };
  const name = (e) => (e.getAttribute("aria-label") || e.textContent || e.name || e.tagName).trim().replace(/\\s+/g, " ").slice(0, 30);
  const out = { small: [], tiny: [], fields: [], text: [] };
  for (const e of document.querySelectorAll("a, button, select, input:not([type=hidden]), textarea, summary, [role=button], [data-tip]")) {
    if (!seen(e) || (e.tagName === "A" && e.closest("p, li > span, .item-note, tr[onclick]"))) continue;  // the row is the target
    if (e.closest("td[data-runs]")) continue;  // on touch the cell is the target, see below
    if (e.getBoundingClientRect().width <= 1) continue;  // hidden for screen readers only, e.g. the radio of a segmented control
    if (e.matches("input[type=checkbox], input[type=radio]") && e.closest("label")) continue;  // the label is the target
    if (e.matches("[data-tip]:not(a, button, select, input, summary)")) continue;
    // The target is the element or its invisible area around it, whichever is larger.
    const r = e.getBoundingClientRect(), around = getComputedStyle(e, "::after");
    const hit = around.position === "absolute" ? [parseFloat(around.width) || 0, parseFloat(around.height) || 0] : [0, 0];
    const w = Math.max(r.width, hit[0]), h = Math.max(r.height, hit[1]);
    if (h < 24 || w < 24) out.tiny.push(name(e));
    else if (e.matches("input, select, textarea")) { if (r.height < 36) out.fields.push(name(e)); }  // no area around a field
    else if ((h < 44 || w < 44) && !e.hasAttribute("data-dense")) out.small.push(name(e));  // dense grids keep 24 px
  }
  for (const e of document.querySelectorAll("td[data-runs]"))
    if (seen(e) && e.getBoundingClientRect().height < 44) out.small.push(e.dataset.runs);
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) { const p = walker.currentNode.parentElement;
    if (walker.currentNode.textContent.trim() && seen(p) && parseFloat(getComputedStyle(p).fontSize) < 12) out.text.push(walker.currentNode.textContent.trim().slice(0, 20)); }
  return out;
}"""


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="obgp-screens-"))
    only = sys.argv[2] if len(sys.argv) > 2 else ""
    out.mkdir(parents=True, exist_ok=True)
    pages = [only] if only.startswith("/") else PAGES  # a path of its own, e.g. a case of the Simulation
    settings = Path(tempfile.mkdtemp(prefix="obgp-screens-settings-"))
    env = {**os.environ, "XDG_CONFIG_HOME": str(settings)}
    searches = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "obgp-lab" / "simulation"
    if searches.is_dir():  # the Simulation shows the searches at hand
        (settings / "obgp-lab").mkdir()
        (settings / "obgp-lab" / "simulation").symlink_to(searches)
    subprocess.run([sys.executable, "-c", f"from lab.web import auth; auth.set_password({PASSWORD!r})"], cwd=REPO, env=env, check=True)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = subprocess.Popen([sys.executable, "-m", "lab.cli", "serve", "--http", "--port", str(port)], cwd=REPO, env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    wide, faults = [], {}
    try:
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.5)
        with sync_playwright() as p:
            for size, (width, height) in SIZES.items():
                # A phone reports a coarse pointer and no hover, which touch emulation alone does not.
                touch = ["--blink-settings=primaryPointerType=2,availablePointerTypes=2,primaryHoverType=1,availableHoverTypes=1"]
                browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM") or None, args=touch if size == "phone" else [])
                for scheme in ("light", "dark"):
                    phone = size == "phone"
                    page = browser.new_context(viewport={"width": width, "height": height}, color_scheme=scheme,
                                               is_mobile=phone, has_touch=phone).new_page()
                    page.goto(base + "/login")
                    page.fill("input[name=password]", PASSWORD)
                    page.press("input[name=password]", "Enter")
                    page.wait_for_load_state()
                    for path in pages:
                        if only not in path:
                            continue
                        page.goto(base + path)
                        page.wait_for_load_state("networkidle")
                        page.wait_for_timeout(500)
                        name = path.strip("/").replace("/", "_").replace("?tab=", "_")
                        page.screenshot(path=out / f"{size}-{scheme}-{name}.png", full_page=True)
                        if page.evaluate("document.documentElement.scrollWidth") > width:
                            wide.append(f"{size} {path}")
                        if phone and scheme == "light":
                            faults[path] = page.evaluate(AUDIT)
                browser.close()
    finally:
        server.terminate()
    print(f"Screenshots in {out}")
    for line in dict.fromkeys(wide):
        print(f"Scrolls sideways: {line}")
    for path, f in faults.items():
        found = [f"{len(f[k])} {what} ({', '.join(dict.fromkeys(f[k]))[:120]})" for k, what in
                 (("tiny", "targets below 24 px"), ("small", "targets below 44 px"), ("fields", "fields below 36 px"), ("text", "texts below 12 px")) if f[k]]
        if found:
            print(f"{path}: " + "; ".join(found))


if __name__ == "__main__":
    main()
