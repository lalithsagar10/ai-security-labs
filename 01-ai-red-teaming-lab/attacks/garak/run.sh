#!/usr/bin/env bash
# Garak scan in the order from PLAN.md. Usage: bash attacks/garak/run.sh [probe-spec] [out-dir]
# Reports land in ~/.local/share/garak/garak_runs/ and are copied to out-dir (default results/garak/).
set -e
cd "$(dirname "$0")/../.."
source .venv-garak/bin/activate

PROBES="${1:-promptinject,encoding.InjectBase64,encoding.InjectROT13,dan.Dan_11_0}"
PREFIX="northwind-$(date +%Y%m%d-%H%M%S)"
garak --config attacks/garak/northwind.yaml --probes "$PROBES" --report_prefix "$PREFIX"

RUNS="$HOME/.local/share/garak/garak_runs"
OUT="${2:-results/garak}"
mkdir -p "$OUT"
cp "$RUNS/$PREFIX".* "$OUT"/ && echo "Copied reports to $OUT/"
