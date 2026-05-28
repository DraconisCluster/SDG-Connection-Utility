#!/usr/bin/env python3
"""Build the Windows easy-install bundle for the SDG Connection Test.

Produces: dist/sdg-connection-test-<version>-windows-x64.zip

Layout (slim — non-technical customer:

  sdg-connection-test/
    README - START HERE.txt
    Run-Test.cmd
    config.txt
    LICENSE.txt
    app/
      node.exe
      NODEJS-LICENSE.txt
      client/client.js
      shared/{netUtils,ports,protocol}.js

Run from anywhere inside the repo:
  python tools/build-bundle.py --host 38.107.232.39

Optional flags:
  --version vX.Y.Z   Override version (default: `git describe --tags --abbrev=0`).
  --node-version vX.Y.Z   Override pinned Node version (default below).
  --output PATH      Override output zip path.

Files are copied from the working tree, not `git archive HEAD`. Make sure
your working tree matches what you want to ship.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

# Pinned Node.js 22 LTS (Jod). Update both fields together when bumping.
# SHA256 is from https://nodejs.org/dist/<version>/SHASUMS256.txt
NODE_VERSION_DEFAULT = "v22.22.2"
NODE_WIN_X64_SHA256 = "7c93e9d92bf68c07182b471aa187e35ee6cd08ef0f24ab060dfff605fcc1c57c"

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
CACHE_DIR = TOOLS_DIR / "cache"
DIST_DIR = REPO_ROOT / "dist"

# Files copied from the source tree into <bundle>/app/. Anything not in
# this list is dropped — the goal is a customer bundle that contains
# only what's needed at run time, not dev docs, tests, or package
# metadata.
APP_FILES = [
    "client/client.js",
    "shared/netUtils.js",
    "shared/ports.js",
    "shared/protocol.js",
]


def detect_version() -> str:
    try:
        r = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        )
        return r.stdout.strip()
    except subprocess.CalledProcessError:
        sys.exit("error: could not determine version from git tags; pass --version")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download_node(node_version: str, expected_sha256: str) -> Path:
    """Download and SHA256-verify the Windows x64 Node zip. Cached."""
    fname = f"node-{node_version}-win-x64.zip"
    url = f"https://nodejs.org/dist/{node_version}/{fname}"
    out = CACHE_DIR / fname

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if out.exists():
        if sha256_file(out) == expected_sha256:
            print(f"[cache] {fname}")
            return out
        print(f"[cache] {fname} hash mismatch, re-downloading")
        out.unlink()

    print(f"[fetch] {url}")
    tmp = out.with_suffix(out.suffix + ".part")
    with urllib.request.urlopen(url) as resp, tmp.open("wb") as f:
        shutil.copyfileobj(resp, f)
    actual = sha256_file(tmp)
    if actual != expected_sha256:
        tmp.unlink()
        sys.exit(
            f"error: SHA256 mismatch for {fname}\n"
            f"  expected: {expected_sha256}\n"
            f"  got:      {actual}"
        )
    tmp.rename(out)
    return out


def extract_node(node_zip: Path, app_dir: Path, node_version: str) -> None:
    """Pull just node.exe (as app/node.exe) and Node's MIT LICENSE
    (as app/NODEJS-LICENSE.txt) out of the upstream Node zip."""
    inner_root = f"node-{node_version}-win-x64"
    app_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(node_zip) as z:
        with z.open(f"{inner_root}/node.exe") as src, (app_dir / "node.exe").open("wb") as dst:
            shutil.copyfileobj(src, dst)
        with z.open(f"{inner_root}/LICENSE") as src, (app_dir / "NODEJS-LICENSE.txt").open("wb") as dst:
            shutil.copyfileobj(src, dst)


def stage_app(stage_root: Path) -> None:
    """Copy runtime-essential source files into <stage_root>/app/."""
    app_dir = stage_root / "app"
    for rel in APP_FILES:
        src = REPO_ROOT / rel
        dst = app_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def write_config(stage_root: Path, target_host: str) -> None:
    config = stage_root / "config.txt"
    config.write_text(
        "# SDG Connection Test - bundle configuration\n"
        "# Edit only if SDG support tells you to.\n"
        "#\n"
        "# TARGET_HOST: the IP (or hostname) of the SDG test server the\n"
        "# launcher should probe. Space Engineers does not resolve DNS,\n"
        "# so this is normally a literal IPv4 address.\n"
        f"TARGET_HOST={target_host}\n",
        encoding="utf-8",
        newline="\r\n",
    )


def write_top_files(stage_root: Path) -> None:
    """Drop the four user-facing files at the bundle root."""
    shutil.copy2(TOOLS_DIR / "Run-Test.cmd", stage_root / "Run-Test.cmd")
    shutil.copy2(TOOLS_DIR / "README-FIRST.txt", stage_root / "README - START HERE.txt")
    shutil.copy2(REPO_ROOT / "LICENSE", stage_root / "LICENSE.txt")


def make_zip(stage_parent: Path, top_dir_name: str, out_zip: Path) -> None:
    """Zip stage_parent/<top_dir_name> as <top_dir_name>/... entries.

    Uses forward-slash entries (Python zipfile default) so unzip and other
    standards-compliant tools handle it cleanly across platforms.
    """
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    if out_zip.exists():
        out_zip.unlink()

    src_root = stage_parent / top_dir_name
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in sorted(src_root.rglob("*")):
            if path.is_dir():
                continue
            arc = path.relative_to(stage_parent).as_posix()
            z.write(path, arc)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", required=True,
                    help="Target server IP or hostname baked into config.txt")
    ap.add_argument("--version", default=None,
                    help="Bundle version, e.g. v1.2.0 (default: latest git tag)")
    ap.add_argument("--node-version", default=NODE_VERSION_DEFAULT,
                    help=f"Node.js version to bundle (default: {NODE_VERSION_DEFAULT})")
    ap.add_argument("--node-sha256", default=NODE_WIN_X64_SHA256,
                    help="Expected SHA256 of node-<ver>-win-x64.zip")
    ap.add_argument("--output", default=None, help="Override output zip path")
    ap.add_argument("--keep-stage", action="store_true",
                    help="Keep the staging dir after build (for debugging)")
    args = ap.parse_args()

    version = args.version or detect_version()
    if not version.startswith("v"):
        version = "v" + version

    out_zip = Path(args.output) if args.output else (
        DIST_DIR / f"sdg-connection-test-{version}-windows-x64.zip"
    )

    stage_parent = DIST_DIR / "_stage"
    if stage_parent.exists():
        shutil.rmtree(stage_parent)
    top_dir_name = "sdg-connection-test"
    stage_root = stage_parent / top_dir_name

    print(f"[build] version      : {version}")
    print(f"[build] target host  : {args.host}")
    print(f"[build] node version : {args.node_version}")
    print(f"[build] output       : {out_zip}")

    node_zip = download_node(args.node_version, args.node_sha256)
    stage_app(stage_root)
    extract_node(node_zip, stage_root / "app", args.node_version)
    write_config(stage_root, args.host)
    write_top_files(stage_root)
    make_zip(stage_parent, top_dir_name, out_zip)

    if not args.keep_stage:
        shutil.rmtree(stage_parent)

    digest = sha256_file(out_zip)
    size = out_zip.stat().st_size
    print()
    print(f"[done] {out_zip}")
    print(f"       size   : {size:,} bytes ({size / 1024 / 1024:.1f} MiB)")
    print(f"       sha256 : {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
