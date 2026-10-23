#!/usr/bin/env python3
"""Pixel verification of the edition-6 widget specimens against the design
PDF itself. The renderers' output (screenshotted at 2x) is compared with the
PDF's own specimen pages after scale normalization: solid colors must match
exactly at probe points, and the normalized raster difference must stay under
the antialiasing budget. Geometry is asserted separately (spec widths).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageChops

REPO = Path(__file__).resolve().parents[2]
SHOTS = REPO / "target" / "website-pixel"
PDF_DIR = SHOTS / "pdf"
PDF = REPO / "KiwiCaptcha_Visual_Identity.pdf"

# name -> (pdf page number, quadrant hint x0,y0,x1,y1 in page pixels)
# specimen -> (pdf page, index among the page's cards in reading order)
CARDS = {
    "status-pending": (5, 0),
    "status-connecting": (5, 1),
    "status-solving": (5, 2),
    "status-done": (5, 3),
    "status-idle": (5, 4),
    "status-expired": (5, 5),
    "status-failed": (6, 0),
    "status-worker-unavailable": (6, 1),
    "status-execution-unavailable": (6, 2),
    "status-solver-mismatch": (6, 3),
    "factor-address": (7, 0),
    "factor-requested": (8, 0),
    "factor-code": (8, 2),
    "status-solving-dark": (12, 0),
    "status-failed-dark": (12, 1),
    "factor-code-dark": (12, 2),
}
DARK_CARDS = {"status-solving-dark", "status-failed-dark", "factor-code-dark"}

# Solid-color probes (fractional coordinates inside the card) must match
# within TOLERANCE; the raster itself may differ by antialiasing only.
PROBES = {
    "card-bg": (0.5, 0.08),
    "card-bg-lower": (0.5, 0.93),
}
TOLERANCE = 6          # /255 per channel for solid probe points
MAE_BUDGET = 10.0      # mean absolute raster difference after normalization
BAD_PIXEL_BUDGET = 0.10  # fraction of pixels differing by more than 36/255


def render_pdf_pages() -> dict[int, Path]:
    PDF_DIR.mkdir(parents=True, exist_ok=True)
    needed = sorted({page for page, _ in CARDS.values()})
    for page in needed:
        out = PDF_DIR / f"page-{page:02d}"
        final = out.with_suffix(".png")
        if final.exists() and final.stat().st_size and "--rerender" in sys.argv:
            final.unlink()
        if not final.exists():
            subprocess.run(
                ["pdftoppm", "-png", "-r", "300", "-f", str(page), "-l", str(page), str(PDF), str(out)],
                check=True,
            )
            # pdftoppm appends the page number to the prefix; normalize.
            for generated in PDF_DIR.glob(f"{out.name}-*.png"):
                generated.rename(final)
    return {page: PDF_DIR / f"page-{page:02d}.png" for page in needed}


def page_cards(im: Image.Image) -> list[tuple[int, int, int, int]]:
    """Find every solid-background card on a page by run-based row bands,
    then split each band into cards by column clustering. Heading antialias
    specks never form long runs, so they cannot inflate a box."""
    px = im.load()
    w, h = im.size
    min_run = w // 12

    def runs_of(y):
        out, run, start = [], 0, None
        for x in range(w):
            r, g, b = px[x, y][:3]
            hit = (
                (abs(r - 0xFB) <= 8 and abs(g - 0xFC) <= 8 and abs(b - 0xF8) <= 8)
                or (abs(r - 0x10) <= 8 and abs(g - 0x22) <= 8 and abs(b - 0x19) <= 8)
            )
            if hit:
                if run == 0:
                    start = x
                run += 1
            else:
                if run >= min_run:
                    out.append((start, x - 1))
                run = 0
        if run >= min_run:
            out.append((start, w - 1))
        return out

    row_runs = [(y, runs_of(y)) for y in range(h)]
    row_runs = [(y, r) for y, r in row_runs if r]
    if not row_runs:
        return []

    # group rows into vertical bands
    bands, current, prev = [], [], None
    for y, r in row_runs:
        if prev is None or y - prev <= 3:
            current.append((y, r))
        else:
            bands.append(current)
            current = [(y, r)]
        prev = y
    if current:
        bands.append(current)

    cards = []
    for band in bands:
        # cluster run x-intervals across the band into columns
        intervals = [iv for _, r in band for iv in r]
        intervals.sort()
        clusters: list[list[int]] = []
        for x0, x1 in intervals:
            if clusters and x0 <= clusters[-1][1] + 40:
                clusters[-1][0] = min(clusters[-1][0], x0)
                clusters[-1][1] = max(clusters[-1][1], x1)
            else:
                clusters.append([x0, x1])
        clusters = [c for c in clusters if c[1] - c[0] >= w // 10]
        for x0, x1 in clusters:
            cards.append((x0, band[0][0], x1, band[-1][0]))
    # Merge vertically-split fragments of one card: full-width controls
    # (primary buttons) break the background run rows, so a card arrives as
    # stacked pieces. Same column with a gap under 200 px is one card; rows
    # of cards sit at least ~240 px apart.
    merged = True
    while merged:
        merged = False
        for i in range(len(cards)):
            for j in range(i + 1, len(cards)):
                a, b = cards[i], cards[j]
                overlap = min(a[2], b[2]) - max(a[0], b[0])
                narrow = min(a[2] - a[0], b[2] - b[0])
                gap = max(a[1], b[1]) - min(a[3], b[3])
                if overlap >= 0.9 * narrow and -5 <= gap <= 200:
                    cards[i] = (
                        min(a[0], b[0]), min(a[1], b[1]),
                        max(a[2], b[2]), max(a[3], b[3]),
                    )
                    cards.pop(j)
                    merged = True
                    break
            if merged:
                break
    # reading order: top-to-bottom, left-to-right within a row band
    cards.sort(key=lambda c: (c[1] // 200, c[0]))
    return cards


def main(argv: list[str]) -> int:
    pages = render_pdf_pages()
    failures: list[str] = []
    widths: dict[str, int] = {}
    rows = 0

    for name, (page, index) in CARDS.items():
        shot_path = SHOTS / f"{name}.png"
        if not shot_path.exists():
            failures.append(f"{name}: specimen screenshot missing (run website-pixel-shots.mjs)")
            continue
        shot = Image.open(shot_path).convert("RGB")

        pdf_page = Image.open(pages[page]).convert("RGB")
        cards = page_cards(pdf_page)
        if index >= len(cards):
            failures.append(f"{name}: page {page} has {len(cards)} cards, need index {index}")
            continue
        box = cards[index]
        if box[2] <= 0:
            failures.append(f"{name}: card not located on PDF page {page}")
            continue
        crop = pdf_page.crop((box[0], box[1], box[2] + 1, box[3] + 1))

        # near-1:1 comparison at the specimen's own container width
        css_w = round(crop.width / 3.125)
        widths[name] = css_w
        target_w = shot.width
        if abs(crop.width - target_w) / target_w > 0.06:
            failures.append(
                f"{name}: render width {target_w} does not match PDF specimen width {crop.width} (css {css_w});"
                " re-run website-pixel-shots.mjs after --measure")
            continue
        crop = crop.resize((target_w, max(1, round(crop.height * target_w / crop.width))), Image.LANCZOS)
        h = min(crop.height, shot.height)
        a = shot.crop((0, 0, target_w, h))
        b = crop.crop((0, 0, target_w, h))

        # solid probes
        probe_ok = True
        for label, (fx, fy) in PROBES.items():
            x = int(target_w * fx); y = int(h * fy)
            pa = a.getpixel((x, y)); pb = b.getpixel((x, y))
            if max(abs(pa[i] - pb[i]) for i in range(3)) > TOLERANCE:
                probe_ok = False
                failures.append(
                    f"{name}: {label} color mismatch render={pa} pdf={pb}"
                )

        diff = ImageChops.difference(a, b).convert("L")
        hist = diff.histogram()
        total = target_w * h
        mae = sum(i * n for i, n in enumerate(hist)) / total
        bad = sum(n for i, n in enumerate(hist) if i > 36) / total
        rows += 1
        status = "ok"
        if mae > MAE_BUDGET or bad > BAD_PIXEL_BUDGET:
            status = "DIFF"
            failures.append(
                f"{name}: raster divergence mae={mae:.2f} bad={bad:.3f} "
                f"(budget mae<={MAE_BUDGET} bad<={BAD_PIXEL_BUDGET})"
            )
        print(f"{name:28} page {page:2}  w={target_w:4}  mae={mae:5.2f}  bad={bad:5.3f}  probes={'ok' if probe_ok else 'FAIL'}  {status}")

    if "--measure" in sys.argv:
        with open(SHOTS / "widths.json", "w") as fh:
            json.dump(widths, fh, indent=2, sort_keys=True)
        print(f"measured {len(widths)} specimen widths -> {SHOTS / 'widths.json'}")

    if failures:
        for f in failures:
            print(f"FAIL {f}", file=sys.stderr)
        print(f"pixel verify: {len(failures)} failure(s) across {rows} specimens", file=sys.stderr)
        return 1
    print(f"pixel verify: PASS ({rows} specimens match the design PDF)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
