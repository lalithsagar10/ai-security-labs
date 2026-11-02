#!/usr/bin/env bash
# Start the Northwind RAG assistant on http://localhost:8001 (Part 1's bot uses :8000).
# Builds the vector DB on first run. Ctrl+C stops it.
set -e
cd "$(dirname "$0")"

if ! curl -s --max-time 3 http://localhost:11434 >/dev/null; then
  echo "❌ Ollama is not running. Start it with: open -a Ollama"
  exit 1
fi

if lsof -ti tcp:8001 -sTCP:LISTEN >/dev/null; then
  echo "❌ Port 8001 is already in use. Stop the old server first:"
  echo "   kill \$(lsof -ti tcp:8001 -sTCP:LISTEN)"
  exit 1
fi

source .venv/bin/activate

if [ ! -d data/chroma ] || [ "$1" = "--reset" ]; then
  echo "▶ Building the vector DB..."
  python -m app.ingest --reset
fi

echo "▶ Starting RAG assistant on http://localhost:8001 ..."
uvicorn app.server:app --port 8001 --reload
