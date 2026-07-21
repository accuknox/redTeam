#!/usr/bin/env bash
set -euo pipefail

echo "==> Installing build deps..."
uv pip install -e ".[build]"

echo "==> Building standalone binary..."
pyinstaller knox_rt.spec --clean

echo ""
echo "Binary ready: dist/knox-rt"
echo "Test it: ./dist/knox-rt --help"
