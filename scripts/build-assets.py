"""Makes the logos and pictures of assets/.

    uv run --with fonttools --with playwright python scripts/build-assets.py

Needs Chromium for Playwright once: uv run --with playwright playwright install chromium

The marks and avatars are drawn by hand (assets/mark*.svg, assets/avatar-*.svg).
Everything with text is made here: the wordmarks, the social preview and the
process of the README. Their text is set in Inter (SIL Open Font License),
downloaded once, and turned into paths, so every SVG and PNG looks the same
on every system. Then the PNGs are rendered from the SVGs.

The files: mark.svg (app icon, favicon), mark-dark.svg (on dark backgrounds),
mark-mono.svg (one colour), logo-{obgp,router,lab}-{light,dark} (wordmarks),
avatar-{router,lab} (profile pictures, cut to a circle), favicon-32.png,
apple-touch-icon.png, icon-512.png, social-preview.png (GitHub → Settings →
Social preview) and readme/ (the pictures of the README). The colour is U of T
Blue, #1e3765, the accent of the interface (--color-uoft-* in lab/web/styles.css).
"""

import base64
import hashlib
import io
import os
import urllib.request
import zipfile
from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
INTER = "https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip"
INTER_SHA256 = "9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "obgp-lab"

# U of T Blue and its scale, as in lab/web/styles.css
UOFT = {50: "#f1f5fe", 100: "#dfe8f9", 200: "#bfd2f3", 300: "#9bb8eb", 400: "#759be0", 500: "#4a6fb5",
        600: "#345695", 700: "#1e3765", 800: "#13274d", 900: "#0a1936"}


def fonts() -> dict[int, TTFont]:
    archive = CACHE / "Inter-4.1.zip"
    if not archive.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        data = urllib.request.urlopen(INTER).read()
        if hashlib.sha256(data).hexdigest() != INTER_SHA256:
            raise SystemExit(f"{INTER} is not the expected file")
        archive.write_bytes(data)
    with zipfile.ZipFile(archive) as z:
        return {w: TTFont(io.BytesIO(z.read(f"extras/ttf/Inter-{name}.ttf")))
                for w, name in ((400, "Regular"), (500, "Medium"), (600, "SemiBold"), (700, "Bold"))}


FONTS = fonts()


def text(s: str, x: float, y: float, size: float, weight: int, fill: str, spacing: float = 0) -> tuple[str, float]:
    """The text as one path, with its baseline at y; and where it ends."""
    font = FONTS[weight]
    glyphs, cmap = font.getGlyphSet(), font.getBestCmap()
    scale = size / font["head"].unitsPerEm
    pen = SVGPathPen(glyphs)
    for ch in s:
        name = cmap[ord(ch)]
        glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x, y)))
        x += font["hmtx"][name][0] * scale + spacing
    return f'<path d="{pen.getCommands()}" fill="{fill}"/>', x - spacing


def tile(size: float, fill: str, line: str) -> str:
    """The mark at a size, as in mark.svg."""
    k = size / 32
    return (f'<rect width="{size}" height="{size}" rx="{8 * k}" fill="{fill}"/>'
            f'<path d="M{9 * k} {22 * k} {16 * k} {9 * k}l{7 * k} {13 * k}H{9 * k}Z" stroke="{line}" stroke-width="{2 * k}" stroke-linejoin="round"/>'
            + "".join(f'<circle cx="{cx * k}" cy="{cy * k}" r="{3 * k}" fill="#fff"/>' for cx, cy in ((16, 9), (9, 22), (23, 22))))


def svg(width: float, height: float, body: str) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {height:.0f}" width="{width:.0f}" height="{height:.0f}" fill="none">\n{body}\n</svg>\n'


def wordmarks() -> dict[str, tuple[float, float]]:
    """OBGP, OBGP Router and OBGP Lab, for light and dark backgrounds; their sizes."""
    sizes = {}
    for mode, (fill, line, ink, sub) in {"light": (UOFT[700], UOFT[200], UOFT[700], UOFT[500]),
                                         "dark": (UOFT[600], UOFT[100], "#ffffff", UOFT[300])}.items():
        for name, suffix in (("obgp", ""), ("router", "Router"), ("lab", "Lab")):
            word, end = text("OBGP", 84, 46, 40, 700, ink, -0.8)
            if suffix:
                rest, end = text(suffix, end + 12, 46, 40, 500, sub, -0.4)
                word += rest
            width = end + 4
            (ASSETS / f"logo-{name}-{mode}.svg").write_text(svg(width, 64, tile(64, fill, line) + word))
            sizes[f"logo-{name}-{mode}"] = (width, 64)
    return sizes


def social_preview() -> None:
    lines = [text("OBGP", 96, 400, 96, 700, "#ffffff", -2)[0],
             text("An oscillation-free BGP router,", 96, 456, 34, 400, UOFT[200])[0],
             text("and a lab to prove it", 96, 500, 34, 400, UOFT[200])[0],
             text("IFIP Networking 2026 · based on GoBGP", 96, 566, 24, 400, UOFT[400])[0]]
    network = f'''<g stroke="{UOFT[700]}" stroke-width="3"><path d="M820 120 980 210 1130 150M980 210 1020 380 1180 450M1020 380 860 470 900 600M860 470 760 330 820 120M760 330 1020 380M1130 150 1180 450"/></g>
<path d="M760 330 1020 380 1180 450" stroke="{UOFT[500]}" stroke-width="4"/>
<g fill="{UOFT[600]}">{"".join(f'<circle cx="{x}" cy="{y}" r="12"/>' for x, y in ((820, 120), (980, 210), (1130, 150), (860, 470), (900, 600)))}</g>
<g fill="{UOFT[300]}">{"".join(f'<circle cx="{x}" cy="{y}" r="14"/>' for x, y in ((760, 330), (1020, 380), (1180, 450)))}</g>'''
    body = f'<rect width="1280" height="640" fill="{UOFT[900]}"/>\n{network}\n<g transform="translate(96 176)">{tile(112, UOFT[600], UOFT[100])}</g>\n' + "\n".join(lines)
    (ASSETS / "social-preview.svg").write_text(svg(1280, 640, body))


# The stages of the lab, with the Lucide icons of its interface (ISC license).
STAGES = [
    ("Topologies", "graph, map, SNDlib, CAIDA", '<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>'),
    ("Scenarios", "steps, failures, policies", '<path d="M10 12h11"/><path d="M10 18h11"/><path d="M10 6h11"/><path d="M4 10h2"/><path d="M4 6h1v4"/><path d="M6 18H4c0-1 2-2 2-3s-1-1.5-2-1"/>'),
    ("Experiments", "variants, runs, queue", '<path d="M14 2v6a2 2 0 0 0 .245.96l5.51 10.08A2 2 0 0 1 18 22H6a2 2 0 0 1-1.755-2.96l5.51-10.08A2 2 0 0 0 10 8V2"/><path d="M6.453 15h11.094"/><path d="M8.5 2h7"/>'),
    ("Results", "metrics, charts, replay", '<path d="M3 3v16a2 2 0 0 0 2 2h16"/><path d="m19 9-5 5-4-4-3 3"/>'),
    ("Wrapped", "claims, trends, records", '<path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"/><path d="M20 3v4"/><path d="M22 5h-4"/><path d="M4 17v2"/><path d="M5 18H3"/>'),
]
STEP = 200  # from one stage to the next
WIDTH = (len(STAGES) - 1) * STEP + 180


def process() -> None:
    for mode, (back, icon, title, note, chevron) in {"light": (UOFT[50], UOFT[700], UOFT[700], "#64748b", "#94a3b8"),
                                                    "dark": (UOFT[800], UOFT[200], "#ffffff", "#94a3b8", "#475569")}.items():
        parts = []
        for i, (name, what, paths) in enumerate(STAGES):
            x = i * STEP
            parts.append(f'<g transform="translate({x} 0)"><rect width="56" height="56" rx="14" fill="{back}"/>'
                         f'<g transform="translate(14 14) scale(1.1667)" stroke="{icon}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">{paths}</g></g>')
            parts.append(text(name, x, 84, 17, 600, title)[0])
            parts.append(text(what, x, 106, 13, 400, note)[0])
            if i < len(STAGES) - 1:
                parts.append(f'<path d="M{x + STEP - 36} 22l6 6-6 6" stroke="{chevron}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')
        (ASSETS / "readme" / f"process-{mode}.svg").write_text(svg(WIDTH, 112, "\n".join(parts)))


def render(sizes: dict[str, tuple[float, float]]) -> None:
    """PNG, SVG, width and height in CSS pixels, device pixel ratio"""
    renders = [
        ("favicon-32.png", "mark.svg", 32, 32, 1),
        ("apple-touch-icon.png", "mark.svg", 180, 180, 1),
        ("icon-512.png", "mark.svg", 512, 512, 1),
        ("avatar-router.png", "avatar-router.svg", 1024, 1024, 1),
        ("avatar-lab.png", "avatar-lab.svg", 1024, 1024, 1),
        ("social-preview.png", "social-preview.svg", 1280, 640, 1),
        *((f"{name}.png", f"{name}.svg", w, h, 2) for name, (w, h) in sizes.items()),
    ]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for png, source, width, height, ratio in renders:
            page = browser.new_page(viewport={"width": round(width), "height": round(height)}, device_scale_factor=ratio)
            data = base64.b64encode((ASSETS / source).read_bytes()).decode()
            page.set_content(f'<body style="margin:0"><img src="data:image/svg+xml;base64,{data}" style="display:block;width:{width}px;height:{height}px">')
            page.wait_for_function("document.images[0].complete")
            page.screenshot(path=ASSETS / png, omit_background=True)
            page.close()
            print(png)
        browser.close()


if __name__ == "__main__":
    sizes = wordmarks()
    social_preview()
    process()
    render(sizes)
