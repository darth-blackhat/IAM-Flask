"""Small server-rendered SVG charts (no chart library, no inline style: colours come from
CSS classes in app.css, with separate dark-mode steps). Every chart has a table view."""

from markupsafe import Markup, escape

W, H = 640, 220
PAD_L, PAD_R, PAD_T, PAD_B = 36, 84, 12, 28        # right pad leaves room for direct labels


def line_chart(labels: list[str], series: dict[str, list[int]], title: str) -> Markup:
    """Lines over time, one CSS class per series (s1, s2, s3 in fixed order)."""
    n = len(labels)
    top = max([1] + [v for vals in series.values() for v in vals])
    step = max(1, -(-top // 4))                       # ~4 gridlines, whole numbers
    top = step * 4
    plot_w, plot_h = W - PAD_L - PAD_R, H - PAD_T - PAD_B

    def x(i: int) -> float:
        return PAD_L + (plot_w * i / max(1, n - 1))

    def y(v: float) -> float:
        return PAD_T + plot_h - plot_h * v / top

    parts = [f'<svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="{escape(title)}">']
    for g in range(0, top + 1, step):                 # recessive grid + y labels
        parts.append(f'<line class="grid" x1="{PAD_L}" x2="{W - PAD_R}" y1="{y(g):.1f}" y2="{y(g):.1f}"/>')
        parts.append(f'<text class="axis" x="{PAD_L - 6}" y="{y(g) + 4:.1f}" text-anchor="end">{g}</text>')
    for i, lab in enumerate(labels):
        if i % 2 == 0 or i == n - 1:
            parts.append(f'<text class="axis" x="{x(i):.1f}" y="{H - 8}" text-anchor="middle">{escape(lab)}</text>')
    for k, (name, vals) in enumerate(series.items(), 1):
        pts = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(vals))
        parts.append(f'<polyline class="line s{k}" points="{pts}"/>')
        for i, v in enumerate(vals):                  # markers: hover shows week + value
            parts.append(f'<circle class="dot s{k}" cx="{x(i):.1f}" cy="{y(v):.1f}" r="4">'
                         f'<title>{escape(name)} · week of {escape(labels[i])}: {v}</title></circle>')
        if vals:                                      # direct label at the line end (text ink)
            parts.append(f'<text class="label" x="{x(n - 1) + 8:.1f}" y="{y(vals[-1]) + 4:.1f}">'
                         f'{escape(name)} {vals[-1]}</text>')
    parts.append("</svg>")
    return Markup("".join(parts))
