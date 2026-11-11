#!/usr/bin/env python3
"""
Version bumper for ha-omada-logger Home Assistant Add-on.
Reads config.yaml as the single source of truth and increments semantic versions.

Usage:
  python3 scripts/bump_version.py           # Bumps patch (e.g. 1.7.0 -> 1.7.1)
  python3 scripts/bump_version.py --minor   # Bumps minor (e.g. 1.7.0 -> 1.8.0)
  python3 scripts/bump_version.py --major   # Bumps major (e.g. 1.7.0 -> 2.0.0)
  python3 scripts/bump_version.py --current # Prints current version
  python3 scripts/bump_version.py --set 2.0.1 # Sets explicit version
"""

import argparse
import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT_DIR / "config.yaml"
APP_PATH = ROOT_DIR / "app.py"


def get_current_version() -> str:
    if not CONFIG_PATH.exists():
        print(f"Error: {CONFIG_PATH} not found", file=sys.stderr)
        sys.exit(1)

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("version:"):
                v = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                if v:
                    return v

    print("Error: 'version:' not found in config.yaml", file=sys.stderr)
    sys.exit(1)


def parse_semver(v: str):
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", v)
    if not match:
        raise ValueError(f"Version '{v}' does not match SemVer (X.Y.Z)")
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    extra = match.group(4)
    return major, minor, patch, extra


def bump(current: str, part: str) -> str:
    major, minor, patch, _ = parse_semver(current)
    if part == "major":
        return f"{major + 1}.0.0"
    elif part == "minor":
        return f"{major}.{minor + 1}.0"
    elif part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        raise ValueError(f"Unknown part to bump: {part}")


def update_file(path: Path, pattern: re.Pattern, replacement: str):
    if not path.exists():
        return
    content = path.read_text(encoding="utf-8")
    new_content, count = pattern.subn(replacement, content, count=1)
    if count > 0:
        path.write_text(new_content, encoding="utf-8")


def set_version(new_version: str):
    # Validate semver
    parse_semver(new_version)

    # 1. Update config.yaml
    cfg_content = CONFIG_PATH.read_text(encoding="utf-8")
    cfg_new, count = re.subn(
        r'^(version:\s*["\']?)([^"\'\n]+)(["\']?)',
        rf'\g<1>{new_version}\g<3>',
        cfg_content,
        flags=re.MULTILINE,
    )
    if count == 0:
        print("Error: Could not replace version in config.yaml", file=sys.stderr)
        sys.exit(1)
    CONFIG_PATH.write_text(cfg_new, encoding="utf-8")

    # 2. Update fallback in app.py if present
    if APP_PATH.exists():
        update_file(
            APP_PATH,
            re.compile(r'(version\s*=\s*["\'])\d+\.\d+\.\d+(["\'])'),
            rf'\g<1>{new_version}\g<2>',
        )


def main():
    parser = argparse.ArgumentParser(description="Bump version for ha-omada-logger")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--patch", action="store_true", help="Increment patch version (default)")
    group.add_argument("--minor", action="store_true", help="Increment minor version")
    group.add_argument("--major", action="store_true", help="Increment major version")
    group.add_argument("--current", action="store_true", help="Print current version and exit")
    group.add_argument("--set", type=str, help="Set explicit version (e.g. 1.8.0)")

    args = parser.parse_args()
    current = get_current_version()

    if args.current:
        print(current)
        return

    if args.set:
        new_version = args.set
    elif args.major:
        new_version = bump(current, "major")
    elif args.minor:
        new_version = bump(current, "minor")
    else:
        new_version = bump(current, "patch")

    set_version(new_version)
    print(f"Version bumped: {current} -> {new_version}")


if __name__ == "__main__":
    main()
