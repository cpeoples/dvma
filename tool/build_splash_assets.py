#!/usr/bin/env python3
"""Pre-process DVMA branding art into splash-screen source images.

The raw brand foreground art (assets/branding/dvma_icon_foreground*.png) carries
a large transparent margin, so when flutter_native_splash centers it at native
size the mark looks tiny. This script trims the transparent bounding box, scales
the mark up to a chosen fraction of a square canvas, and composites it onto the
DVMA brand background so the launch screen reads large and on-brand.

Outputs (consumed by config/flutter_native_splash.yaml):
  assets/branding/splash/dvma_splash_light.png        (brand light base)
  assets/branding/splash/dvma_splash_dark.png         (brand dark base)
  assets/branding/splash/dvma_splash_android12.png       (transparent mark)
  assets/branding/splash/dvma_splash_android12_dark.png  (transparent mark)

Usage (requires Pillow; use a throwaway venv if the system Python is managed):
  python3 -m venv .venv && .venv/bin/pip install Pillow
  .venv/bin/python tool/build_splash_assets.py
Then regenerate the native splash:
  dart run flutter_native_splash:create --path config/flutter_native_splash.yaml
"""

from pathlib import Path

from PIL import Image

# Brand base colors - mirror lib/core/theme/dvma_colors.dart (DvmaPalette).
DARK_BASE = (0x0D, 0x12, 0x10, 255)  # green-black
LIGHT_BASE = (0xF4, 0xF6, 0xF4, 255)  # warm off-white paper

# How far to pull the phone-body colors toward the dark base (0 = fully merged
# into the background, 1 = unchanged). 0.3 keeps only a faint outline so the
# amber hazard mark is the clear hero.
PHONE_DARKEN_FACTOR = 0.3

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "branding" / "splash"
FG = ROOT / "assets" / "branding" / "dvma_icon_foreground.png"
FG_DARK = ROOT / "assets" / "branding" / "dvma_icon_foreground_dark.png"


def _is_phone(r: int, g: int, b: int) -> bool:
    """True for the green-gray phone body/outline (not amber, not deep black)."""
    if r > 180 and g > 130 and b < 130:
        return False  # amber mark - leave it alone
    if r < 32 and g < 32 and b < 32:
        return False  # deep-black screen - already merges
    if r > 200 and g > 200 and b > 200:
        return False  # white/glow highlight
    # phone body ~ (51,65,58), outline ~ (159,182,170): greenish, g dominant.
    return (g >= r) and (g >= b) and (g > 30) and (b >= r - 10)


def _darken_phone(im: Image.Image, factor: float, base) -> Image.Image:
    """Pull only the phone-body colors `factor` of the way toward `base`."""
    if factor >= 1.0:
        return im
    px = im.load()
    br, bg, bb, _ = base
    for y in range(im.height):
        for x in range(im.width):
            r, g, b, a = px[x, y]
            if a > 0 and _is_phone(r, g, b):
                px[x, y] = (
                    int(br + (r - br) * factor),
                    int(bg + (g - bg) * factor),
                    int(bb + (b - bb) * factor),
                    a,
                )
    return im


def _trim(im: Image.Image) -> Image.Image:
    """Crop to the non-transparent bounding box."""
    im = im.convert("RGBA")
    bbox = im.split()[3].getbbox()
    return im.crop(bbox) if bbox else im


def make(src: Path, out: Path, fill=None, canvas: int = 1152, mark_ratio: float = 0.62) -> None:
    """Trim `src`, scale the mark to `mark_ratio` of a square `canvas`, center.

    `fill=None` produces a transparent canvas (Android 12+ icon API draws the
    mark on the platform window background); otherwise the mark is composited
    onto the solid brand color.
    """
    mark = _trim(Image.open(src))
    mark = _darken_phone(mark, PHONE_DARKEN_FACTOR, DARK_BASE)
    target = int(canvas * mark_ratio)
    w, h = mark.size
    scale = target / max(w, h)
    mark = mark.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)
    bg = Image.new("RGBA", (canvas, canvas), fill if fill else (0, 0, 0, 0))
    bg.alpha_composite(mark, ((canvas - mark.size[0]) // 2, (canvas - mark.size[1]) // 2))
    out.parent.mkdir(parents=True, exist_ok=True)
    bg.save(out)
    print(f"wrote {out.relative_to(ROOT)}  mark={mark.size}  canvas={canvas}")


def main() -> None:
    make(FG, OUT / "dvma_splash_light.png", LIGHT_BASE)
    make(FG_DARK, OUT / "dvma_splash_dark.png", DARK_BASE)
    make(FG, OUT / "dvma_splash_android12.png", None, mark_ratio=0.66)
    make(FG_DARK, OUT / "dvma_splash_android12_dark.png", None, mark_ratio=0.66)


if __name__ == "__main__":
    main()
