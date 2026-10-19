"""Логотип ScanHub «Поворот»: мастер-файлы SVG.

Знак: синяя табличка (как таблички в окне ScanHub) с белой окантовкой, внутри S — дорожная стрелка «вперёд».
Надпись: Bahnschrift SemiBold (шрифт окна), буквы переведены в контуры — в файлах нет живого текста.
Запуск: python -X utf8 build_logo.py → папка final/.
"""
import os

from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "final")
os.makedirs(OUT, exist_ok=True)
BLUE, BLUE_DARK, WHITE, INK = "#2456D6", "#3563E9", "#FFFFFF", "#141820"

# ---------------------------------------------------------------- знак
S_PATH = "M86 176C101 195 146 197 159 175C172 153 152 141 130 132C110 124 84 114 95 92C102 78 118 74 138 74"
ARROW = "M134 50L175.57 74L134 98Z"          # остриё под 60°, рёбра ровно 30°


def symbol(tile, ink, edge=True, title="ScanHub"):
    """Табличка 224×224 (r 48) на поле 256, белая окантовка на отступе 14, S-стрелка штрихом 26."""
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <title>{title}</title>
  <rect x="16" y="16" width="224" height="224" rx="48" fill="{tile}"/>
  {f'<rect x="30" y="30" width="196" height="196" rx="36" fill="none" stroke="{ink}" stroke-width="7"/>' if edge else ''}
  <path d="{S_PATH}" fill="none" stroke="{ink}" stroke-width="26" stroke-linecap="round"/>
  <path d="{ARROW}" fill="{ink}" stroke="{ink}" stroke-width="8" stroke-linejoin="round"/>
</svg>
'''


# для 16–32 px: табличка на всё поле, без тонкой окантовки (в 16 px она сливается), S толще, стрелка крупнее
S_SMALL = "M70 186C88 210 150 212 166 182C182 152 154 138 128 128C102 118 66 104 80 74C88 58 108 52 132 52"
ARROW_SMALL = "M126 18L184.89 52L126 86Z"


def symbol_small(tile, ink, title="ScanHub"):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <title>{title}</title>
  <rect x="0" y="0" width="256" height="256" rx="56" fill="{tile}"/>
  <g transform="translate(2 8)">
    <path d="{S_SMALL}" fill="none" stroke="{ink}" stroke-width="40" stroke-linecap="round"/>
    <path d="{ARROW_SMALL}" fill="{ink}" stroke="{ink}" stroke-width="10" stroke-linejoin="round"/>
  </g>
</svg>
'''


# ---------------------------------------------------------------- надпись (контуры Bahnschrift SemiBold)
def wordmark_path(text="ScanHub", height=104, tracking=0.0):
    """Контуры надписи: высота заглавных = height. Возвращает (d, ширина)."""
    f = TTFont(r"C:\Windows\Fonts\bahnschrift.ttf")
    if "fvar" in f:
        f = instancer.instantiateVariableFont(f, {"wght": 600, "wdth": 100})
    gs, cmap = f.getGlyphSet(), f.getBestCmap()
    cap = f["OS/2"].sCapHeight or 700
    k = height / cap
    pen = SVGPathPen(gs)
    x = 0.0
    hmtx = f["hmtx"]
    for ch in text:
        gname = cmap[ord(ch)]
        tp = TransformPen(pen, (k, 0, 0, -k, x, height))      # y вниз, базовая линия на height
        gs[gname].draw(tp)
        x += hmtx[gname][0] * k + tracking
    bp = BoundsPen(gs)
    return pen.getCommands(), x - tracking


def lockup(tile, ink_sym, ink_text, edge=True):
    """Горизонтальный: знак 256 + отступ 44 + надпись (высота заглавных 104 — 0,46 знака), выравнивание по центру."""
    d, w = wordmark_path()
    gap, cap = 44, 104
    y = (256 - cap) / 2
    total = 256 + gap + w
    inner = symbol(tile, ink_sym, edge).split("\n", 2)[2].rsplit("</svg>", 1)[0]
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total:.0f} 256">
  <title>ScanHub</title>
{inner}  <path transform="translate({256 + gap} {y:.1f})" d="{d}" fill="{ink_text}"/>
</svg>
'''


def wordmark(ink):
    d, w = wordmark_path()
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="-4 -6 {w + 8:.0f} 118">
  <title>ScanHub</title>
  <path d="{d}" fill="{ink}"/>
</svg>
'''


# ---------------------------------------------------------------- одноцветная версия: S и окантовка — вырезы в табличке
def _cubic_points(d, n=48):
    """Точки центральной линии из пути вида M x y C … C … (только M и C — так нарисована S)."""
    import re
    nums = [float(v) for v in re.findall(r"-?\d+(?:\.\d+)?", d)]
    p0, rest, pts = (nums[0], nums[1]), nums[2:], []
    for i in range(0, len(rest), 6):
        c1, c2, p3 = (rest[i], rest[i + 1]), (rest[i + 2], rest[i + 3]), (rest[i + 4], rest[i + 5])
        for k in range(n + (1 if i + 6 >= len(rest) else 0)):
            t = k / n
            mt = 1 - t
            pts.append((mt ** 3 * p0[0] + 3 * mt * mt * t * c1[0] + 3 * mt * t * t * c2[0] + t ** 3 * p3[0],
                        mt ** 3 * p0[1] + 3 * mt * mt * t * c1[1] + 3 * mt * t * t * c2[1] + t ** 3 * p3[1]))
        p0 = p3
    return pts


def _poly_path(geom):
    from shapely.geometry import MultiPolygon
    polys = list(geom.geoms) if isinstance(geom, MultiPolygon) else [geom]
    out = []
    for p in polys:
        for ring in [p.exterior, *p.interiors]:
            c = list(ring.coords)
            out.append("M" + " L".join(f"{x:.2f} {y:.2f}" for x, y in c[:-1]) + "Z")
    return " ".join(out)


def symbol_mono(color, small=False, title="ScanHub"):
    import re
    from shapely.geometry import LineString, Polygon, box
    if small:
        tile = box(56, 56, 200, 200).buffer(56, quad_segs=24)
        s = LineString([(x + 2, y + 8) for x, y in _cubic_points(S_SMALL)]).buffer(20, quad_segs=16)
        ar = [float(v) for v in re.findall(r"-?\d+(?:\.\d+)?", ARROW_SMALL)]
        arrow = Polygon([(ar[i] + 2, ar[i + 1] + 8) for i in (0, 2, 4)]).buffer(5, quad_segs=8)
        cut = s.union(arrow)
    else:
        tile = box(64, 64, 192, 192).buffer(48, quad_segs=24)
        edge = LineString(list(box(66, 66, 190, 190).buffer(36, quad_segs=24).exterior.coords)).buffer(3.5, quad_segs=8)
        s = LineString(_cubic_points(S_PATH)).buffer(13, quad_segs=16)
        ar = [float(v) for v in re.findall(r"-?\d+(?:\.\d+)?", ARROW)]
        arrow = Polygon([(ar[i], ar[i + 1]) for i in (0, 2, 4)]).buffer(4, quad_segs=8)
        cut = s.union(arrow).union(edge)
    shape = tile.difference(cut).simplify(0.12)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <title>{title}</title>
  <path fill-rule="evenodd" fill="{color}" d="{_poly_path(shape)}"/>
</svg>
'''


files = {
    "scanhub-symbol-mono-black.svg": symbol_mono("#000000"),
    "scanhub-symbol-mono-blue.svg": symbol_mono(BLUE),
    "scanhub-symbol-mono-white.svg": symbol_mono(WHITE),
    "scanhub-symbol-small-mono-black.svg": symbol_mono("#000000", small=True),
    "scanhub-symbol.svg": symbol(BLUE, WHITE),
    "scanhub-symbol-dark.svg": symbol(BLUE_DARK, WHITE),
    "scanhub-symbol-black.svg": symbol("#000000", WHITE),
    "scanhub-symbol-white.svg": symbol(WHITE, BLUE),                 # на синем или тёмном фоне
    "scanhub-symbol-small.svg": symbol_small(BLUE, WHITE),
    "scanhub-symbol-small-black.svg": symbol_small("#000000", WHITE),
    "scanhub-horizontal.svg": lockup(BLUE, WHITE, INK),
    "scanhub-horizontal-on-dark.svg": lockup(BLUE_DARK, WHITE, WHITE),
    "scanhub-horizontal-black.svg": lockup("#000000", WHITE, "#000000"),
    "scanhub-wordmark.svg": wordmark(INK),
    "scanhub-wordmark-white.svg": wordmark(WHITE),
}
for name, svg in files.items():
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
        fh.write(svg)
print("\n".join(files))
