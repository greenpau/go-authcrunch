"""Exercise the UI import target with complete and invalid portable exports."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
APPS = ("profile", "operator", "documents")


class UIAppsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="authcrunch UI import ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        script = self.root / "assets/scripts/update_ui_apps.py"
        script.parent.mkdir(parents=True)
        shutil.copy2(REPO / "assets/scripts/update_ui_apps.py", script)
        shutil.copy2(REPO / "Makefile", self.root / "Makefile")
        self.source = self.root / "portable bundles"
        self.source.mkdir()
        (self.source / "apps.json").write_text(json.dumps({"applications": [
            {"slug": app, "version": "1.2.3"} for app in APPS]}))
        for app in APPS:
            for filename, content in {
                "index.html": '<base href="__AUTHCRUNCH_APP_BASE_PATH__" />',
                "manifest.json": "{}", "logo.svg": "<svg/>", "favicon.svg": "<svg/>",
                "i18n/en.json": "{}", "assets/_chunk.js": "export default 42",
            }.items():
                file = self.source / app / filename
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(content)
            old = self.root / "pkg/authn/ui" / app
            old.mkdir(parents=True)
            (old / "obsolete.js").write_text("previous")

    def command(self):
        return subprocess.run(["make", "ui-apps", "UI_APPS_SOURCE=" + str(self.source)],
                              cwd=self.root, capture_output=True, text=True, timeout=15)

    def test_e2e_imports_all_apps_and_removes_stale_assets_without_editing_source(self):
        self.assertEqual(self.command().returncode, 0)
        for app in APPS:
            target = self.root / "pkg/authn/ui" / app
            self.assertFalse((target / "obsolete.js").exists())
            self.assertEqual((target / "assets/_chunk.js").read_text(), "export default 42")
            self.assertEqual((target / "index.html").read_bytes(), (self.source / app / "index.html").read_bytes())
        self.assertEqual(self.command().returncode, 0, "reimport must be repeatable")

    def test_e2e_refuses_incomplete_or_nonportable_exports_before_replacing_apps(self):
        for mode in ("missing app", "absolute base", "symlink", "missing translation", "unsupported file"):
            with self.subTest(mode=mode):
                file = self.source / "documents/index.html"
                file.write_text('<base href="__AUTHCRUNCH_APP_BASE_PATH__" />')
                extra = self.source / "documents/assets/rejected"
                if extra.exists() or extra.is_symlink():
                    extra.unlink()
                if mode == "missing app":
                    file.unlink()
                elif mode == "absolute base":
                    file.write_text('<base href="/xauth/documents/" />')
                elif mode == "symlink":
                    extra.symlink_to(file)
                elif mode == "missing translation":
                    (self.source / "documents/i18n/en.json").unlink()
                else:
                    extra.write_text("unsupported")
                result = self.command()
                self.assertNotEqual(result.returncode, 0)
                for app in APPS:
                    self.assertEqual((self.root / "pkg/authn/ui" / app / "obsolete.js").read_text(), "previous")
                (self.source / "documents/i18n/en.json").write_text("{}")


if __name__ == "__main__":
    unittest.main()
