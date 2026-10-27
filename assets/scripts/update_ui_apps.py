"""Import a portable AuthCrunch UI export without building a sibling checkout."""

import argparse
import json
from pathlib import Path
import shutil
import tempfile


ROOT = Path(__file__).resolve().parents[2]
APPS = ("profile", "operator", "documents")
BASE = '<base href="__AUTHCRUNCH_APP_BASE_PATH__" />'
EXTENSIONS = {".html", ".js", ".css", ".json", ".svg", ".txt", ".woff2", ".woff", ".ttf", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".eot", ".xml"}


def import_apps(source, root=ROOT):
    source = Path(source).resolve()
    target = root / "pkg/authn/ui"
    manifest = json.loads((source / "apps.json").read_text())
    apps = manifest["applications"]
    if len(apps) != len(APPS) or {app["slug"] for app in apps} != set(APPS):
        raise ValueError("Export must contain profile, operator and documents exactly once")
    for app in apps:
        if not isinstance(app.get("version"), str) or not app["version"]:
            raise ValueError("Export requires application versions")
    # Validate the complete export before replacing any checked-in app.
    for app in APPS:
        directory = source / app
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("Missing application directory")
        for file in directory.rglob("*"):
            if file.is_symlink() or any(part.startswith(".") for part in file.relative_to(directory).parts):
                raise ValueError("Hidden files and symlinks are not supported in application exports")
            if file.is_file() and file.suffix not in EXTENSIONS:
                raise ValueError("Unsupported application asset extension")
        html = (directory / "index.html").read_text()
        if html.count(BASE) != 1:
            raise ValueError("Application HTML requires one portable base marker")
        for required in ("manifest.json", "logo.svg", "favicon.svg", "i18n/en.json"):
            if not (directory / required).is_file():
                raise ValueError("Application export is incomplete")
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ui-import-", dir=target) as temporary:
        temporary = Path(temporary)
        for app in APPS:
            shutil.copytree(source / app, temporary / app)
        moved, installed = [], []
        try:
            for app in APPS:
                destination = target / app
                if destination.exists():
                    destination.rename(temporary / (app + ".previous"))
                    moved.append(app)
                (temporary / app).rename(destination)
                installed.append(app)
        except OSError:
            for app in installed:
                shutil.rmtree(target / app)
            for app in moved:
                (temporary / (app + ".previous")).rename(target / app)
            raise
    print("Imported " + ", ".join(f"{app['slug']} {app['version']}" for app in apps))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "../../authcrunch/authcrunch-ui/dist/embedded")
    args = parser.parse_args()
    try:
        import_apps(args.source)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"UI import failed: {error}\nRun npm run export::apps in the UI repository first.\n")


if __name__ == "__main__":
    main()
