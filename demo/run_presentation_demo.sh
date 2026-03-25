#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIP_PATH="${ROOT_DIR}/demo/synthetic_lab/synthetic_sharphound.zip"
OUT_DIR="${1:-/tmp/vsoh_demo}"

if [[ ! -f "${ZIP_PATH}" ]]; then
  echo "Synthetic demo ZIP not found: ${ZIP_PATH}" >&2
  exit 1
fi

echo "[1/2] Running AD Analyzer demo..."
"${ROOT_DIR}/.venv/bin/ad-analyzer" analyze "${ZIP_PATH}" --out "${OUT_DIR}" --html --pdf

echo "[2/2] Demo artifacts ready:"
echo "  ${OUT_DIR}/artifacts/findings.json"
echo "  ${OUT_DIR}/artifacts/findings.csv"
echo "  ${OUT_DIR}/artifacts/summary.json"
echo "  ${OUT_DIR}/artifacts/report.md"
echo "  ${OUT_DIR}/artifacts/report.html"
echo "  ${OUT_DIR}/artifacts/report.pdf"
