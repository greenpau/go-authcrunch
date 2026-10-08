#!/usr/bin/env python3
"""Check release projections and compute versioned CI artifact identities."""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
VERSION_PATTERN = re.compile(r"1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
TARGETS = ("cmd/authdb/main.go", "cmd/authdbctl/main.go", "pkg/identity/database.go")

OPENAPI_SOURCE = Path("assets/openapi/content/openapi.yaml")
OPENAPI_INFO_PATTERN = re.compile(r"^(?:info|'info'|\"info\")\s*:", re.MULTILINE)
OPENAPI_VERSION_KEY = re.compile(r"^  (?:version|'version'|\"version\")\s*:", re.MULTILINE)
OPENAPI_VERSION_PATTERN = re.compile(
    r"^(  version: )(1\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))(?=\n|$)", re.MULTILINE)


def read_version(root=ROOT):
    raw = (root / "VERSION").read_text(encoding="utf-8")
    version = raw.removesuffix("\n")
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("VERSION must be exactly 1.<minor>.<patch>, without leading zeros or suffixes")
    # versioned uses uint64 components. Reject values it cannot increment safely.
    if any(int(part) >= 2**64 - 1 for part in version.split(".")):
        raise ValueError("VERSION components must leave room for a versioned increment")
    return version


def check_version(root=ROOT, tag=None):
    version = read_version(root)
    for target in TARGETS:
        text = (root / target).read_text(encoding="utf-8")
        for field, variable, expected in (
            ("Version", "appVersion", version),
            ("GitBranch", "gitBranch", ""),
            ("GitCommit", "gitCommit", ""),
        ):
            values = re.findall(r'app\.Set' + field + r'\(' + variable + r', "([^"]*)"\)', text)
            if values != [expected]:
                raise ValueError(f"{target}: Set{field} fallback is not synchronized; run make version-sync")
    _, api_version = openapi_version(root)
    if api_version.group(2) != version:
        raise ValueError("OpenAPI info.version differs from VERSION; run make version-sync")
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"release tag must equal v{version}")
    return version


def sync_version(root=ROOT):
    version = read_version(root)
    source, match = openapi_version(root)
    for target in TARGETS:
        subprocess.run(["go", "tool", "versioned", "-release", "-sync", target], cwd=root, check=True)
    if match.group(2) != version:
        updated = source[:match.start(2)] + version + source[match.end(2):]
        (root / OPENAPI_SOURCE).write_bytes(updated.encode("utf-8"))
    return check_version(root)


def openapi_version(root):
    """Locate the plain, two-space info.version field in the owned YAML format.

    This is a narrow text projection, not a general YAML parser. Full YAML/OAS
    validation belongs to make openapi; ambiguous or reformatted version fields
    fail closed rather than letting release automation rewrite the document.
    """
    source = (root / OPENAPI_SOURCE).read_bytes().decode("utf-8")
    infos = list(OPENAPI_INFO_PATTERN.finditer(source))
    if (len(infos) != 1 or not source[infos[0].start():].startswith("info:\n")
            or "\r" in source or re.search(r"^(?:---|\.\.\.)", source, re.MULTILINE)):
        raise ValueError("expected one plain OpenAPI info block in a single LF-delimited YAML document")
    start = infos[0].end() + 1
    boundary = re.search(r"^[^\s#]", source[start:], re.MULTILINE)
    end = start + boundary.start() if boundary else len(source)
    keys = list(OPENAPI_VERSION_KEY.finditer(source, start, end))
    matches = list(OPENAPI_VERSION_PATTERN.finditer(source, start, end))
    if len(keys) != 1 or len(matches) != 1:
        raise ValueError("expected one plain OpenAPI info.version line: '  version: 1.<minor>.<patch>'")
    return source, matches[0]


def next_version(version, kind):
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("invalid release version")
    major, minor, patch = map(int, version.split("."))
    if kind == "minor":
        minor, patch = minor + 1, 0
    elif kind == "patch":
        patch += 1
    else:
        raise ValueError("only patch and minor releases are supported")
    if minor >= 2**64 - 1 or patch >= 2**64 - 1:
        raise ValueError("next version exceeds the supported versioned range")
    return f"{major}.{minor}.{patch}"


def artifact_identity(version, sha, ref_type, ref_name, timestamp=None):
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("invalid artifact version")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("artifact commit must be a full lowercase Git SHA")
    if ref_type == "tag":
        if ref_name != f"v{version}":
            raise ValueError(f"release tag must equal v{version}")
        return f"v{version}"
    if ref_type != "branch":
        raise ValueError("artifact ref type must be branch or tag")
    stamp = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", stamp):
        raise ValueError("invalid UTC artifact timestamp")
    return f"v{version}_{stamp}_{sha[:12]}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "sync", "artifact", "next"))
    parser.add_argument("--tag")
    parser.add_argument("--kind", choices=("patch", "minor"), default="patch")
    args = parser.parse_args()
    try:
        if args.command == "sync":
            print(f"Synchronized version {sync_version()}")
        elif args.command == "check":
            print(f"Version {check_version(tag=args.tag)} is synchronized")
        elif args.command == "next":
            print(next_version(check_version(), args.kind))
        else:
            version = check_version()
            sha = os.environ.get("GITHUB_SHA") or subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            ref_type = os.environ.get("GITHUB_REF_TYPE", "branch")
            artifact = artifact_identity(version, sha, ref_type, os.environ.get("GITHUB_REF_NAME", ""))
            print(artifact)
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                    output.write(f"version={version}\nartifact_id={artifact}\n")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Version check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
