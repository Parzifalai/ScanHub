🇷🇺 [Русская версия](README.ru.md)

# ScanHub logo — "Arrow-S"

**Idea.** The letter S, with its upper tail extending to the right as an arrow: "forward, we'll sort it out". ScanHub doesn't scare people with a shield; it shows what's wrong and walks you through the steps. The arrowhead sticks out past the edge of the letter, so even at 16 px the mark reads as an arrow rather than a "$".

## Files

| File | Where to use |
|---|---|
| `scanhub-symbol.svg` | main mark — from 64 px |
| `scanhub-symbol-small.svg` | for 16–48 px: thicker stroke, simpler curves, larger arrowhead (window icon, taskbar, tab) |
| `scanhub-symbol-dark.svg`, `scanhub-symbol-small-dark.svg` | on a dark background (lighter blue) |
| `scanhub-symbol-white.svg`, `scanhub-symbol-small-white.svg` | white — on blue, dark or photo backgrounds |
| `scanhub-symbol-black.svg`, `scanhub-symbol-small-black.svg` | black-and-white print, engraving |
| `scanhub-horizontal.svg` | mark + wordmark on a light background (README, websites) |
| `scanhub-horizontal-on-dark.svg` | mark + wordmark on a dark background |
| `scanhub-horizontal-black.svg`, `scanhub-horizontal-white.svg` | single-color horizontal versions |
| `scanhub-wordmark.svg`, `scanhub-wordmark-white.svg` | wordmark only |
| `scanhub-512.png`, `scanhub-1024.png` | raster mark (avatars, social networks) |

Window and program icons: `ui/logo.svg`, `ui/logo-small.svg`, `ui/icon-32.png`, `ui/icon-256.png`, `ui/scanhub.ico` (16–256 px; the small mark is used up to 48 px), the `ScanHub.exe` icon. They are built by the scripts `dev/build_logo.py` → `dev/export_icons.py`.

## Color

| | HEX | RGB | Where |
|---|---|---|---|
| ScanHub blue | `#2F63E8` | 47 99 232 | mark on a light background, program icons |
| Blue on dark | `#4A7BF7` | 74 123 247 | mark on a dark background |
| Graphite | `#141820` | 20 24 32 | wordmark on a light background |
| White | `#FFFFFF` | 255 255 255 | wordmark on dark, white mark |

The blue `#2F63E8` was chosen so the mark is visible both on white (contrast 5.2:1) and on the dark Windows taskbar (3.2:1); icons need at least 3:1. On a dark background, `#4A7BF7` gives 4.2:1.

## Typeface

The wordmark is set in Bahnschrift SemiBold (the window's UI font), with the letters converted to outlines: the files contain no live text, so the font is not needed to display them.

## Rules

- **Clear space** around the mark: at least the height of the arrowhead.
- **Minimum size:** main mark — 64 px, small mark — 16 px; horizontal version — 120 px wide.
- **Background:** light — blue mark; dark — `-dark`; blue, colored or photo — `-white`.
- **Don't:** separate or remove the arrow, flip the arrow the other way, recolor to other colors, stretch, add outlines, shadows or gradients, put the wordmark to the left of the mark or set it in another typeface.
