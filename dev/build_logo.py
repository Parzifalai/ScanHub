"""Логотип ScanHub «Стрелка-S»: мастер-файлы SVG.

Знак: синяя S, верхний хвост которой уходит вправо стрелкой — «вперёд, разберёмся»: ScanHub показывает, что не так,
и ведёт по шагам. Без таблички, без щита. Остриё вынесено за край буквы, чтобы в мелком размере не читалось как «$».
Надпись: Bahnschrift SemiBold (шрифт окна), буквы переведены в контуры — в файлах нет живого текста.
Запуск: python -X utf8 build_logo.py → папка final/ (рядом со скриптом).
"""
import os

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "final")
os.makedirs(OUT, exist_ok=True)
BLUE, BLUE_DARK, WHITE, BLACK, INK = "#2F63E8", "#4A7BF7", "#FFFFFF", "#000000", "#141820"

# основной знак (от 64 px): штрих 34, остриё под 60°; сдвиг — оптический центр чуть выше геометрического
S_PATH = "M44 194C64 222 128 224 146 190C164 156 134 140 108 130C80 120 46 108 60 76C70 54 96 50 150 50"
ARROW = "M150 14L212.35 50L150 86Z"
SHIFT = "translate(0 11)"
# мелкий знак (16–48 px): штрих 46, изгибы проще, остриё крупнее
S_SMALL = "M34 196C58 232 132 232 152 190C170 150 132 136 104 126C74 116 32 102 50 66C60 46 90 42 146 42"
ARROW_SMALL = "M140 0L209.28 40L140 80Z"
SHIFT_SMALL = "translate(6 14)"


def _mark(color, small=False):
    s, a, sh, w, aw = (S_SMALL, ARROW_SMALL, SHIFT_SMALL, 46, 12) if small else (S_PATH, ARROW, SHIFT, 34, 10)
    return (f'<g transform="{sh}">\n'
            f'    <path d="{s}" fill="none" stroke="{color}" stroke-width="{w}" stroke-linecap="round"/>\n'
            f'    <path d="{a}" fill="{color}" stroke="{color}" stroke-width="{aw}" stroke-linejoin="round"/>\n  </g>')


def symbol(color, small=False):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <title>ScanHub</title>
  {_mark(color, small)}
</svg>
'''


def wordmark_path(text="ScanHub", height=104):
    """Контуры надписи Bahnschrift SemiBold: высота заглавных = height. Возвращает (d, ширина)."""
    f = TTFont(r"C:\Windows\Fonts\bahnschrift.ttf")
    if "fvar" in f:
        f = instancer.instantiateVariableFont(f, {"wght": 600, "wdth": 100})
    gs, cmap = f.getGlyphSet(), f.getBestCmap()
    k = height / (f["OS/2"].sCapHeight or 700)
    pen, x = SVGPathPen(gs), 0.0
    for ch in text:
        g = cmap[ord(ch)]
        gs[g].draw(TransformPen(pen, (k, 0, 0, -k, x, height)))
        x += f["hmtx"][g][0] * k
    return pen.getCommands(), x


def lockup(mark_color, text_color):
    """Горизонтальный: знак + надпись. Знак обрезан по своим полям (слева 44, справа ~40) — расстояние до надписи 40."""
    d, w = wordmark_path()
    left, mark_w, gap, cap = 40, 176, 40, 104
    x_text = mark_w + gap
    total = x_text + w + 8
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total:.0f} 256">
  <title>ScanHub</title>
  <g transform="translate({-left} 0)">{_mark(mark_color)}</g>
  <path transform="translate({x_text} {(256 - cap) / 2 + 4:.1f})" d="{d}" fill="{text_color}"/>
</svg>
'''


def wordmark(color):
    d, w = wordmark_path()
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="-4 -6 {w + 8:.0f} 118">
  <title>ScanHub</title>
  <path d="{d}" fill="{color}"/>
</svg>
'''


files = {
    "scanhub-symbol.svg": symbol(BLUE),
    "scanhub-symbol-dark.svg": symbol(BLUE_DARK),              # на тёмном фоне
    "scanhub-symbol-black.svg": symbol(BLACK),
    "scanhub-symbol-white.svg": symbol(WHITE),                 # на синем, фото, тёмном
    "scanhub-symbol-small.svg": symbol(BLUE, small=True),
    "scanhub-symbol-small-dark.svg": symbol(BLUE_DARK, small=True),
    "scanhub-symbol-small-black.svg": symbol(BLACK, small=True),
    "scanhub-symbol-small-white.svg": symbol(WHITE, small=True),
    "scanhub-horizontal.svg": lockup(BLUE, INK),
    "scanhub-horizontal-on-dark.svg": lockup(BLUE_DARK, WHITE),
    "scanhub-horizontal-black.svg": lockup(BLACK, BLACK),
    "scanhub-horizontal-white.svg": lockup(WHITE, WHITE),
    "scanhub-wordmark.svg": wordmark(INK),
    "scanhub-wordmark-white.svg": wordmark(WHITE),
}
for f in os.listdir(OUT):                                       # старые файлы прошлого варианта логотипа
    if f.endswith(".svg") and f not in files:
        os.remove(os.path.join(OUT, f))
for name, svg in files.items():
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
        fh.write(svg)
print("\n".join(files))
