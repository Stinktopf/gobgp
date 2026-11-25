"""The simulator's map of the README, light and dark: a finding played step by step, the routers' routes,
the messages on their way and a router's reason in its bubble. Run from the repository root with the search
in this lab's settings (MCP tool download, lab pull):
uv run --with playwright --with pillow python scripts/dev/readme-simulator.py [search] [finding] [step]"""

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright
from screens import REPO, login, serve

SEARCH = sys.argv[1] if len(sys.argv) > 1 else "20261114115156362657"
FINDING = sys.argv[2] if len(sys.argv) > 2 else "345"  # DISAGREE: r1 and r2 prefer each other's route
STEP = sys.argv[3] if len(sys.argv) > 3 else "9"  # packets circle between r1 and r2
MARGIN = 16  # CSS pixels around what the map draws


def trim(src: Path, dark: bool, pad: int = 24) -> None:
    """Crops to what is drawn, on the page's own background."""
    from PIL import Image, ImageChops
    im = Image.open(src).convert("RGB")
    box = ImageChops.difference(im, Image.new("RGB", im.size, im.getpixel((0, 0)))).convert("L").point(lambda v: 255 if v > 24 else 0).getbbox()
    if box:
        im.crop((max(box[0] - pad, 0), max(box[1] - pad, 0), min(box[2] + pad, im.width), min(box[3] + pad, im.height))).save(src)


def main() -> None:
    out = REPO / "assets" / "readme"
    with serve() as base, sync_playwright() as p:
        browser = p.chromium.launch()
        for scheme in ("light", "dark"):
            page = browser.new_context(viewport={"width": 1180, "height": 1000}, color_scheme=scheme, device_scale_factor=2).new_page()
            login(page, base)
            page.goto(f"{base}/simulation/{SEARCH}/{FINDING}")
            while not page.locator("[data-counter]").inner_text().strip().startswith(f"{STEP} "):
                page.locator("[data-act=next]").click(timeout=60000)
                page.wait_for_timeout(300)
            page.wait_for_timeout(1200)
            page.add_style_tag(content="body > header, body > nav { display: none !important; }")
            graph = page.locator("[data-map]")
            graph.scroll_into_view_if_needed()
            box = graph.evaluate("""(svg) => { let a = [1e9, 1e9, -1e9, -1e9];
                for (const el of svg.children) { const r = el.getBoundingClientRect(); if (!r.width || !r.height) continue;
                    a = [Math.min(a[0], r.left), Math.min(a[1], r.top), Math.max(a[2], r.right), Math.max(a[3], r.bottom)]; }
                return {x: a[0] + scrollX, y: a[1] + scrollY, width: a[2] - a[0], height: a[3] - a[1]}; }""")
            page.evaluate("window.scrollTo(0, 0)")
            path = out / f"simulator-{scheme}.png"
            page.screenshot(path=path, full_page=True, clip={"x": max(box["x"] - MARGIN, 0), "y": max(box["y"] - MARGIN, 0),
                                                            "width": box["width"] + 2 * MARGIN, "height": box["height"] + 2 * MARGIN})
            trim(path, scheme == "dark")
        browser.close()


if __name__ == "__main__":
    main()
