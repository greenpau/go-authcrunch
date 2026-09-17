"""SVG branding, shared palette validation, and executable regeneration tests."""

import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


SCRIPT = Path(__file__).resolve().parents[1] / "update_brand_assets.py"
REPO = SCRIPT.parents[2]
spec = importlib.util.spec_from_file_location("authcrunch_brand_assets", SCRIPT)
branding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(branding)
NS = {"svg": "http://www.w3.org/2000/svg"}


class BrandAssetsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="authcrunch-brand-assets-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("assets/scripts/update_brand_assets.py", "assets/branding/palette.json",
                     "assets/branding/soft-square.svg", "pkg/authn/ui/core/css/basic.css",
                     "pkg/authn/ui/profile/manifest.json", "pkg/authn/ui/profile/index.html"):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / name, destination)

    def command(self, *args):
        return subprocess.run([sys.executable, str(self.root / "assets/scripts/update_brand_assets.py"), *args],
                              cwd=self.root, capture_output=True, text=True, timeout=15)

    def test_palette_rejects_missing_unknown_and_invalid_colors(self):
        path = self.root / "assets/branding/palette.json"
        palette = json.loads(path.read_text())
        invalid = [[], {**palette, "unknown": "#123456"},
                   {key: value for key, value in palette.items() if key != "ink"}]
        invalid += [{**palette, "primary": value} for value in (None, "red", "#abc", "#123456;}", "#12gh56")]
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                path.write_text(json.dumps(candidate))
                with self.assertRaises(ValueError):
                    branding.read_palette(self.root)

    def test_each_svg_keeps_the_selected_geometry_and_native_paths(self):
        source = ET.parse(self.root / "assets/branding/soft-square.svg")
        expected = {node.attrib["id"]: node.attrib["d"] for node in source.findall(".//svg:path", NS)}
        for path, content in branding.render(self.root).items():
            if path.suffix != ".svg":
                continue
            with self.subTest(path=path):
                svg = ET.fromstring(content)
                self.assertEqual(svg.tag, "{" + NS["svg"] + "}svg")
                if path.name in ("banner.svg", "background.svg"):
                    self.assertFalse(svg.findall(".//svg:use", NS), "decoration must not repeat the logo")
                    for name, data in expected.items():
                        self.assertIsNone(svg.find(f".//*[@id='{name}']"))
                        self.assertNotIn(data, [node.get("d") for node in svg.findall(".//svg:path", NS)])
                else:
                    for name, data in expected.items():
                        self.assertEqual(svg.find(f".//svg:path[@id='{name}']", NS).attrib["d"], data)
                self.assertFalse(svg.findall(".//svg:image", NS))
                self.assertFalse(svg.findall(".//svg:script", NS))
                for node in svg.iter():
                    if "href" in node.attrib:
                        self.assertTrue(node.attrib["href"].startswith("#"))

    def test_e2e_palette_recolors_artwork_css_and_profile_without_geometry_drift(self):
        self.assertEqual(self.command().returncode, 0)
        self.assertEqual(self.command("--check").returncode, 0)
        palette_path = self.root / "assets/branding/palette.json"
        palette = json.loads(palette_path.read_text())
        palette.update(primary="#6238a8", ink="#302040", page="#f5f0fb")
        palette_path.write_text(json.dumps(palette))
        logo_path = self.root / "pkg/authn/ui/core/images/logo.svg"
        original = logo_path.read_bytes()
        self.assertEqual(self.command("--check").returncode, 1)
        self.assertEqual(logo_path.read_bytes(), original, "check mode changed an artifact")
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.command("--check").returncode, 0)
        for path in (self.root / "pkg/authn/ui").rglob("*.svg"):
            svg = ET.parse(path)
            if path.name in ("banner.svg", "background.svg"):
                paints = {value for node in svg.iter() for key, value in node.attrib.items()
                          if key in ("fill", "stroke", "stop-color") and value.startswith("#")}
                self.assertIn("#6238a8", paints)
                self.assertIn("#302040", paints)
                self.assertLessEqual(paints, set(palette.values()), "decoration has colors outside the palette")
            else:
                self.assertEqual(svg.find(".//svg:path[@id='brand-primary']", NS).attrib["stroke"], "#6238a8")
                self.assertEqual(svg.find(".//svg:path[@id='brand-ink']", NS).attrib["stroke"], "#302040")
        css = (self.root / "pkg/authn/ui/core/css/basic.css").read_text()
        self.assertIn("--brand-primary: #6238a8;", css)
        self.assertIn("--brand-ink: #302040;", css)
        manifest = json.loads((self.root / "pkg/authn/ui/profile/manifest.json").read_text())
        self.assertEqual(manifest["theme_color"], "#6238a8")
        self.assertEqual(manifest["background_color"], "#f5f0fb")
        self.assertEqual(manifest["icons"][0]["type"], "image/svg+xml")
        self.assertIn('name="theme-color" content="#6238a8"', (self.root / "pkg/authn/ui/profile/index.html").read_text())

    def test_svg_paint_references_resolve_without_external_resources(self):
        for path, content in branding.render(self.root).items():
            if path.suffix != ".svg":
                continue
            with self.subTest(path=path):
                svg = ET.fromstring(content)
                ids = [node.attrib["id"] for node in svg.iter() if "id" in node.attrib]
                self.assertEqual(len(ids), len(set(ids)), "duplicate SVG identifiers")
                for node in svg.iter():
                    for value in node.attrib.values():
                        for reference in re.findall(r"url\(([^)]+)\)", value):
                            self.assertTrue(reference.startswith("#"), "external paint resource")
                            self.assertIn(reference[1:], ids, "unresolved paint server")

    def test_e2e_invalid_input_does_not_partially_rewrite_assets(self):
        self.assertEqual(self.command().returncode, 0)
        expected = {path: (self.root / path).read_bytes() for path in branding.render(self.root)}
        source = self.root / "assets/branding/soft-square.svg"
        source.write_text(source.read_text().replace('id="brand-ink"', 'id="missing"'))
        result = self.command()
        self.assertEqual(result.returncode, 2)
        self.assertIn("brand-ink", result.stderr)
        for path, content in expected.items():
            self.assertEqual((self.root / path).read_bytes(), content)

    def test_source_metadata_is_optional_and_badge_stays_behind_geometry(self):
        source = self.root / "assets/branding/soft-square.svg"
        original = source.read_text()
        for metadata in ("none", "title only", "after geometry"):
            with self.subTest(metadata=metadata):
                svg = ET.fromstring(original)
                for node in list(svg):
                    if node.tag.endswith("}title") or node.tag.endswith("}desc"):
                        svg.remove(node)
                if metadata != "none":
                    title = ET.Element("{" + NS["svg"] + "}title")
                    title.text = "Edited mark"
                    svg.insert(0 if metadata == "title only" else len(svg), title)
                if metadata == "after geometry":
                    ET.SubElement(svg, "{" + NS["svg"] + "}desc").text = "Edited description"
                source.write_text(ET.tostring(svg, encoding="unicode"))
                output = branding.render(self.root)
                icon = ET.fromstring(output[Path("pkg/authn/ui/core/images/favicon.svg")])
                children = list(icon)
                self.assertLess(children.index(icon.find("svg:rect", NS)), children.index(icon.find("svg:g", NS)))
                self.assertTrue(icon.find("svg:desc", NS).text)
                result = self.command()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.command("--check").returncode, 0)


if __name__ == "__main__":
    unittest.main()
