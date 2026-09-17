"""Generate the portal/profile SVG artwork and shared colors from one palette."""

import argparse
import copy
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
SVG = "http://www.w3.org/2000/svg"
ET.register_namespace("", SVG)
COLOR_KEYS = {
    "primary", "primary_hover", "on_primary", "ink", "muted", "surface",
    "soft", "page", "border", "control_border", "banner_edge",
    "background_start", "background_middle", "background_end",
}
CSS_COLORS = (
    "page", "surface", "soft", "ink", "muted", "primary", "on_primary",
    "primary_hover", "border", "control_border",
)
UI = Path("pkg/authn/ui")
CSS = UI / "core/css/basic.css"
PROFILE = UI / "profile"


def read_palette(root):
    palette = json.loads((root / "assets/branding/palette.json").read_text())
    if not isinstance(palette, dict) or palette.keys() != COLOR_KEYS:
        raise ValueError("brand palette must contain exactly the documented color keys")
    if any(not isinstance(value, str) or not re.fullmatch(r"#[0-9a-fA-F]{6}", value)
           for value in palette.values()):
        raise ValueError("brand palette colors must use #RRGGBB notation")
    return {key: value.lower() for key, value in palette.items()}


def serialize(element):
    ET.indent(element, space="  ")
    return ET.tostring(element, encoding="unicode") + "\n"


def replace_once(pattern, replacement, text, description):
    result, count = re.subn(pattern, lambda _: replacement, text, flags=re.DOTALL)
    if count != 1:
        raise ValueError(f"expected one {description}, found {count}")
    return result


def render(root):
    palette = read_palette(root)
    logo = ET.parse(root / "assets/branding/soft-square.svg").getroot()
    for name in ("primary", "ink"):
        nodes = logo.findall(f".//{{{SVG}}}path[@id='brand-{name}']")
        if len(nodes) != 1:
            raise ValueError(f"source mark must contain one brand-{name} path")
        nodes[0].set("stroke", palette[name])
    group = logo.find(f"{{{SVG}}}g")
    if group is None:
        raise ValueError("source mark is missing its geometry group")

    favicon = copy.deepcopy(logo)
    description = favicon.find(f"{{{SVG}}}desc")
    if description is None:
        description = ET.SubElement(favicon, f"{{{SVG}}}desc")
    description.text = "AuthCrunch linked-trust icon on a light rounded badge."
    badge = ET.Element(f"{{{SVG}}}rect", {"width": "512", "height": "512", "rx": "112", "fill": palette["page"]})
    favicon_group = favicon.find(f"{{{SVG}}}g")
    # Metadata is optional and may move when a vector editor saves the source.
    # Paint the badge before the mark, independent of metadata ordering.
    favicon.insert(list(favicon).index(favicon_group), badge)
    favicon_group.set("transform", "translate(256 256) scale(1.38) rotate(-45) translate(-256 -256)")

    # The card uses a narrow saturated accent. The viewport artwork has a
    # separate composition, so the header never looks like a cropped backdrop.
    banner = f'''<svg xmlns="{SVG}" viewBox="0 0 1200 40" preserveAspectRatio="none" fill="none">
  <title>AuthCrunch blue and navy horizon accent</title>
  <defs>
    <linearGradient id="banner-horizon" x1="0" y1="0" x2="1200" y2="0" gradientUnits="userSpaceOnUse">
      <stop stop-color="{palette['ink']}"/>
      <stop offset=".42" stop-color="{palette['primary']}"/>
      <stop offset=".64" stop-color="{palette['primary']}"/>
      <stop offset="1" stop-color="{palette['ink']}"/>
    </linearGradient>
    <linearGradient id="banner-light" x1="0" y1="0" x2="1200" y2="0" gradientUnits="userSpaceOnUse">
      <stop stop-color="{palette['banner_edge']}" stop-opacity="0"/>
      <stop offset=".5" stop-color="{palette['banner_edge']}" stop-opacity=".6"/>
      <stop offset="1" stop-color="{palette['banner_edge']}" stop-opacity="0"/>
    </linearGradient>
  </defs>
  <path fill="url(#banner-horizon)" d="M0 0h1200v40H0z"/>
  <path fill="url(#banner-light)" d="M0 0h1200v5H0z"/>
</svg>'''
    # Flowing contours stay at the edges of the page. All paint comes from the
    # palette, including transparent gradient stops; no filters or bitmaps.
    left_contours = "\n".join(
        f'    <path d="M-120 {130 + i * 38} C{180 + i * 16} {10 + i * 28} '
        f'{420 + i * 12} {200 + i * 32} {290 + i * 12} {410 + i * 30} '
        f'S{70 + i * 8} {700 + i * 26} -100 {810 + i * 24}"/>'
        for i in range(9)
    )
    right_contours = "\n".join(
        f'    <path d="M{1310 + i * 26} -80 C{1090 + i * 20} {120 + i * 16} '
        f'{1190 + i * 24} {310 + i * 18} {1410 + i * 20} {410 + i * 22} '
        f'S{1750 + i * 16} {760 + i * 20} {1430 + i * 22} 1100"/>'
        for i in range(9)
    )
    background = f'''<svg xmlns="{SVG}" viewBox="0 0 1600 1000" fill="none">
  <title>AuthCrunch luminous blue background with flowing edge contours</title>
  <defs>
    <linearGradient id="page-sky" x1="0" y1="0" x2="1600" y2="1000" gradientUnits="userSpaceOnUse">
      <stop stop-color="{palette['background_start']}"/>
      <stop offset=".5" stop-color="{palette['background_middle']}"/>
      <stop offset="1" stop-color="{palette['background_end']}"/>
    </linearGradient>
    <radialGradient id="left-light" cx="160" cy="230" r="650" gradientUnits="userSpaceOnUse">
      <stop stop-color="{palette['primary']}" stop-opacity=".22"/>
      <stop offset="1" stop-color="{palette['primary']}" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="right-light" cx="1510" cy="820" r="720" gradientUnits="userSpaceOnUse">
      <stop stop-color="{palette['primary']}" stop-opacity=".18"/>
      <stop offset="1" stop-color="{palette['primary']}" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="center-light" cx="800" cy="300" r="600" gradientUnits="userSpaceOnUse">
      <stop stop-color="{palette['surface']}" stop-opacity=".8"/>
      <stop offset="1" stop-color="{palette['surface']}" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="contour-blue" x1="0" y1="0" x2="530" y2="700" gradientUnits="userSpaceOnUse">
      <stop stop-color="{palette['primary']}" stop-opacity=".24"/>
      <stop offset="1" stop-color="{palette['primary']}" stop-opacity=".035"/>
    </linearGradient>
    <linearGradient id="contour-navy" x1="1600" y1="100" x2="1130" y2="900" gradientUnits="userSpaceOnUse">
      <stop stop-color="{palette['ink']}" stop-opacity=".12"/>
      <stop offset="1" stop-color="{palette['primary']}" stop-opacity=".08"/>
    </linearGradient>
  </defs>
  <path fill="url(#page-sky)" d="M0 0h1600v1000H0z"/>
  <path fill="url(#left-light)" d="M0 0h1600v1000H0z"/>
  <path fill="url(#right-light)" d="M0 0h1600v1000H0z"/>
  <path fill="url(#center-light)" d="M0 0h1600v1000H0z"/>
  <g stroke="url(#contour-blue)" stroke-width="1.5">
{left_contours}
  </g>
  <g stroke="url(#contour-navy)" stroke-width="1.5">
{right_contours}
  </g>
</svg>'''
    images = {
        "logo.svg": serialize(logo), "favicon.svg": serialize(favicon),
        "banner.svg": serialize(ET.fromstring(banner)),
        "background.svg": serialize(ET.fromstring(background)),
    }
    output = {UI / "core/images" / name: content for name, content in images.items()}
    output.update({PROFILE / "logo.svg": images["logo.svg"],
                   PROFILE / "favicon.svg": images["favicon.svg"],
                   PROFILE / "images/banner.svg": images["banner.svg"]})

    colors = ["  /* BEGIN BRAND COLORS */", "  /* Generated from assets/branding/palette.json. */"]
    colors.extend(f"  --brand-{key.replace('_', '-')}: {palette[key]};" for key in CSS_COLORS)
    colors += [f"  --brand-focus: {palette['primary']};",
               f"  --brand-shadow: 0 12px 40px {palette['ink']}12, 0 2px 6px {palette['ink']}06;",
               "  /* END BRAND COLORS */"]
    output[CSS] = replace_once(r"  /\* BEGIN BRAND COLORS \*/.*?/\* END BRAND COLORS \*/",
                               "\n".join(colors), (root / CSS).read_text(), "CSS palette block")
    manifest_path = PROFILE / "manifest.json"
    manifest = json.loads((root / manifest_path).read_text())
    manifest["icons"] = [{"src": "logo.svg", "type": "image/svg+xml", "sizes": "any", "purpose": "any"}]
    manifest["theme_color"], manifest["background_color"] = palette["primary"], palette["page"]
    output[manifest_path] = json.dumps(manifest, indent=2) + "\n"
    index_path = PROFILE / "index.html"
    output[index_path] = replace_once(r'<meta name="theme-color" content="[^"]*"\s*/>',
                                      f'<meta name="theme-color" content="{palette["primary"]}" />',
                                      (root / index_path).read_text(), "profile theme-color meta tag")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report drift without writing files")
    args = parser.parse_args()
    try:
        # Render and validate every input before modifying any output.
        output = render(ROOT)
        changed = [path for path, content in output.items()
                   if not (ROOT / path).exists() or (ROOT / path).read_text() != content]
        if args.check:
            if changed:
                print("Brand assets are out of date: " + ", ".join(map(str, changed)), file=sys.stderr)
                return 1
            print("Brand assets and palette are synchronized.")
            return 0
        for path in changed:
            (ROOT / path).parent.mkdir(parents=True, exist_ok=True)
            (ROOT / path).write_text(output[path])
        print(f"Updated {len(changed)} brand files from assets/branding/palette.json.")
        return 0
    except (OSError, ValueError, ET.ParseError) as error:
        print(f"Brand asset generation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
