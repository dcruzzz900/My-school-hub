"""Tiny dependency-free SVG chart helpers (bar, line, donut). Output is self-contained, scales to any width,
prints cleanly and needs no JavaScript or external CDN. All text is escaped."""
from html import escape
from markupsafe import Markup

PALETTE = ["#1f6feb", "#2da44e", "#f0883e", "#a371f7", "#d1242f", "#0ea5a5", "#bf8700", "#6e7781", "#e85aad", "#3fb950"]


def _fmt(v):
    return f"{v:.1f}".rstrip("0").rstrip(".") if isinstance(v, float) else str(v)


def bar_chart(items, title, unit="", max_value=None, horizontal=None, color=None):
    """items: [(label, value)]. Horizontal bars when labels are long or numerous."""
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items:
        return empty(title)
    horizontal = horizontal if horizontal is not None else (len(items) > 6 or max(len(l) for l, _ in items) > 10)
    top = max_value or max(max(v for _, v in items), 1)
    if horizontal:
        row_h, left, width = 26, 130, 560
        h = row_h * len(items) + 12
        parts = [f'<svg viewBox="0 0 {width} {h}" role="img" aria-label="{escape(title)}" class="chart">']
        for i, (l, v) in enumerate(items):
            y = 6 + i * row_h
            w = (width - left - 60) * (v / top)
            parts.append(f'<text x="{left-8}" y="{y+15}" text-anchor="end" font-size="11">{escape(l[:22])}</text>')
            parts.append(f'<rect x="{left}" y="{y+3}" width="{max(w,1):.1f}" height="{row_h-9}" rx="3" fill="{color or PALETTE[i % len(PALETTE)] if len(items) <= 1 else (color or PALETTE[0])}"><title>{escape(l)}: {_fmt(v)}{unit}</title></rect>')
            parts.append(f'<text x="{left+w+6:.1f}" y="{y+15}" font-size="11" font-weight="700">{_fmt(round(v,1))}{unit}</text>')
        parts.append("</svg>")
    else:
        width, height, left, bottom = 560, 220, 36, 34
        n = len(items)
        slot = (width - left - 10) / n
        bw = min(48, slot * 0.6)
        parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}" class="chart">']
        for g in range(5):
            gy = 10 + (height - bottom - 20) * g / 4
            parts.append(f'<line x1="{left}" x2="{width-6}" y1="{gy:.1f}" y2="{gy:.1f}" stroke="#e5e7eb"/>')
            parts.append(f'<text x="{left-4}" y="{gy+4:.1f}" text-anchor="end" font-size="9" fill="#666">{_fmt(round(top*(4-g)/4,1))}</text>')
        for i, (l, v) in enumerate(items):
            x = left + i * slot + (slot - bw) / 2
            bh = (height - bottom - 20) * (v / top)
            y = height - bottom - bh
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{max(bh,1):.1f}" rx="3" fill="{color or PALETTE[i % len(PALETTE)]}"><title>{escape(l)}: {_fmt(v)}{unit}</title></rect>')
            parts.append(f'<text x="{x+bw/2:.1f}" y="{y-4:.1f}" text-anchor="middle" font-size="10" font-weight="700">{_fmt(round(v,1))}{unit}</text>')
            parts.append(f'<text x="{x+bw/2:.1f}" y="{height-bottom+14}" text-anchor="middle" font-size="10">{escape(l[:12])}</text>')
        parts.append("</svg>")
    return Markup("".join(parts))


def line_chart(points, title, unit="", max_value=None):
    """points: [(label, value or None)] in order."""
    pts = [(str(l), None if v is None else float(v)) for l, v in points]
    vals = [v for _, v in pts if v is not None]
    if len(vals) < 1:
        return empty(title)
    width, height, left, bottom = 560, 220, 36, 34
    top = max_value or max(max(vals) * 1.1, 1)
    n = max(len(pts) - 1, 1)
    def xy(i, v):
        return left + (width - left - 14) * i / n, 10 + (height - bottom - 20) * (1 - v / top)
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}" class="chart">']
    for g in range(5):
        gy = 10 + (height - bottom - 20) * g / 4
        parts.append(f'<line x1="{left}" x2="{width-6}" y1="{gy:.1f}" y2="{gy:.1f}" stroke="#e5e7eb"/>')
        parts.append(f'<text x="{left-4}" y="{gy+4:.1f}" text-anchor="end" font-size="9" fill="#666">{_fmt(round(top*(4-g)/4,1))}</text>')
    path = " ".join(("M" if k == 0 else "L") + f"{xy(i, v)[0]:.1f},{xy(i, v)[1]:.1f}" for k, (i, v) in enumerate((i, v) for i, (_, v) in enumerate(pts) if v is not None))
    parts.append(f'<path d="{path}" fill="none" stroke="{PALETTE[0]}" stroke-width="2.5"/>')
    step = max(1, len(pts) // 8)
    for i, (l, v) in enumerate(pts):
        if v is None:
            continue
        x, y = xy(i, v)
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{PALETTE[0]}"><title>{escape(l)}: {_fmt(round(v,1))}{unit}</title></circle>')
        if i % step == 0 or i == len(pts) - 1:
            parts.append(f'<text x="{x:.1f}" y="{height-bottom+14}" text-anchor="middle" font-size="9">{escape(l[-10:])}</text>')
    parts.append("</svg>")
    return Markup("".join(parts))


def donut_chart(items, title, center_label=""):
    import math
    items = [(str(l), float(v or 0)) for l, v in items if (v or 0) > 0]
    total = sum(v for _, v in items)
    if not items or total <= 0:
        return empty(title)
    cx, cy, r, sw = 90, 90, 62, 26
    parts = [f'<svg viewBox="0 0 360 180" role="img" aria-label="{escape(title)}" class="chart chart-donut">']
    if len(items) == 1:
        parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{PALETTE[0]}" stroke-width="{sw}"><title>{escape(items[0][0])}: {_fmt(items[0][1])}</title></circle>')
    else:
        circ = 2 * math.pi * r
        off = 0.0
        for i, (l, v) in enumerate(items):
            seg = circ * v / total
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{PALETTE[i % len(PALETTE)]}" stroke-width="{sw}" stroke-dasharray="{seg:.2f} {circ-seg:.2f}" stroke-dashoffset="{-off:.2f}" transform="rotate(-90 {cx} {cy})"><title>{escape(l)}: {_fmt(v)} ({v*100/total:.0f}%)</title></circle>')
            off += seg
    parts.append(f'<text x="{cx}" y="{cy-2}" text-anchor="middle" font-size="20" font-weight="700">{_fmt(int(total) if total == int(total) else round(total,1))}</text>')
    parts.append(f'<text x="{cx}" y="{cy+14}" text-anchor="middle" font-size="10" fill="#555">{escape(center_label)}</text>')
    for i, (l, v) in enumerate(items[:8]):
        y = 22 + i * 18
        parts.append(f'<rect x="190" y="{y-9}" width="11" height="11" rx="2" fill="{PALETTE[i % len(PALETTE)]}"/>')
        parts.append(f'<text x="206" y="{y}" font-size="11">{escape(l[:18])} — {_fmt(int(v) if v == int(v) else round(v,1))} ({v*100/total:.0f}%)</text>')
    parts.append("</svg>")
    return Markup("".join(parts))


def empty(title):
    return Markup(f'<p class="muted chart-empty">No data yet for “{escape(title)}”.</p>')
