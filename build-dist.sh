#!/bin/bash
#
# build-dist.sh -- builds the release package for one version:
#   1. docker build (linux/amd64) + docker save -> image.tar
#   2. dist/DnacEyesightSync-<ver>.zip that unpacks into a folder of the
#      SAME name, with Deploy.sh / Remove.sh / fw-helper.sh stored 0755.
#
# The zip is written with Python's zipfile so the entries carry Unix
# modes and forward-slash paths regardless of the host OS -- the v2 zip
# (2026-09-18) unpacked flat with every file mode 0 and the scripts
# not executable, which is exactly what this exists to prevent.
#
# Usage: ./build-dist.sh v3        (dist/ is gitignored; the zip is the release asset)
set -euo pipefail

VER="${1:?usage: ./build-dist.sh <version, e.g. v3>}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="dnac-eyesight-sync"
PKG="DnacEyesightSync-${VER}"
OUT_DIR="${DIR}/dist"
ZIP_PATH="${OUT_DIR}/${PKG}.zip"

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1 || { echo "python not found" >&2; exit 1; }
PY="$(command -v python3 || command -v python)"

echo "=== 1. Building the image (linux/amd64) ==="
docker build --provenance=false --platform linux/amd64 -t "${IMAGE_NAME}:latest" "$DIR"

echo
echo "=== 2. Exporting image.tar ==="
docker save -o "${DIR}/image.tar" "${IMAGE_NAME}:latest"
echo "image.tar $(du -h "${DIR}/image.tar" | cut -f1)"

echo
echo "=== 3. Building ${ZIP_PATH} ==="
mkdir -p "$OUT_DIR"
"$PY" - "$DIR" "$PKG" "$ZIP_PATH" <<'EOF'
import os, sys, zipfile
src, pkg, out = sys.argv[1], sys.argv[2], sys.argv[3]
files = [
    "Deploy.sh", "Remove.sh", "fw-helper.sh", "README-Deploy.md", "image.tar",
    "Dockerfile", "requirements.txt", "build-dist.sh", ".gitignore",
    "app.py", "dnac_client.py", "eyesight_client.py", "fw_client.py", "scheduler.py", "sync_engine.py",
]
for d in ("templates", "static"):
    for root, _, names in os.walk(os.path.join(src, d)):
        for n in sorted(names):
            files.append(os.path.relpath(os.path.join(root, n), src).replace(os.sep, "/"))
EXEC = {"Deploy.sh", "Remove.sh", "fw-helper.sh", "build-dist.sh"}
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for rel in files:
        path = os.path.join(src, rel)
        if not os.path.isfile(path):
            sys.exit(f"missing {rel}")
        info = zipfile.ZipInfo(f"{pkg}/{rel}")
        info.compress_type = zipfile.ZIP_STORED if rel == "image.tar" else zipfile.ZIP_DEFLATED
        info.create_system = 3  # Unix -- so unzip on the EM honours the mode bits
        info.external_attr = ((0o755 if rel in EXEC else 0o644) << 16)
        with open(path, "rb") as f:
            z.writestr(info, f.read())
        print("  added", info.filename, oct(info.external_attr >> 16))
EOF
echo
echo "=== Done: ${ZIP_PATH} ($(du -h "$ZIP_PATH" | cut -f1)) -- unpacks into ${PKG}/ ==="
