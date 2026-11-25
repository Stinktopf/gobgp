"""The replay of the README, light and dark: BAD GADGET, BGP beside OBGP, at one
moment. Run from the repository root with a result that holds it:
uv run --with playwright python scripts/dev/readme-replay.py [result] [seconds]"""

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright
from screens import REPO, login, serve

RESULT = sys.argv[1] if len(sys.argv) > 1 else "smoke-scale-20261113"
AT_S = float(sys.argv[2]) if len(sys.argv) > 2 else 13.6
PATH = f"/results/{RESULT}?tab=replay&topology=bad-gadget&scenario=smoke-drain&run=1"


def main() -> None:
    out = REPO / "assets" / "readme"
    with serve() as base, sync_playwright() as p:
        browser = p.chromium.launch()
        for scheme in ("light", "dark"):
            page = browser.new_context(viewport={"width": 1180, "height": 900}, color_scheme=scheme, device_scale_factor=2).new_page()
            login(page, base)
            page.goto(base + PATH)
            page.wait_for_selector("[data-pane]:not([hidden]) canvas")
            page.wait_for_function("!document.querySelector('[data-pane]:not([hidden]) [data-loading]:not([hidden])')")
            page.eval_on_selector("[data-scrub]", "(e, t) => { e.value = t * 10; e.dispatchEvent(new Event('input')); }", AT_S)
            page.wait_for_timeout(800)
            panes = page.locator("[data-pane]").first.locator("xpath=..")
            panes.screenshot(path=Path(out / f"replay-{scheme}.png"))
        browser.close()


if __name__ == "__main__":
    main()
