#!/usr/bin/env bash
# Start the Northwind lab: chatbot target (:8000) + red-team console (:7860).
# Ctrl+C stops both.
set -e
cd "$(dirname "$0")"

if ! curl -s --max-time 3 http://localhost:11434 >/dev/null; then
  echo "❌ Ollama is not running. Start it with: open -a Ollama"
  exit 1
fi

for port in 8000 7860; do
  if lsof -ti tcp:"$port" -sTCP:LISTEN >/dev/null; then
    echo "❌ Port $port is already in use. Stop the old server first:"
    echo "   kill \$(lsof -ti tcp:$port -sTCP:LISTEN)"
    exit 1
  fi
done

source .venv-pyrit/bin/activate

echo "▶ Starting chatbot on http://localhost:8000 ..."
uvicorn app.chatbot:app --port 8000 --reload &
API_PID=$!
trap 'echo; echo "■ Stopping..."; kill $API_PID 2>/dev/null' EXIT

until curl -s http://localhost:8000/health >/dev/null; do sleep 0.5; done
echo "✅ Chatbot ready"

echo "▶ Starting console on http://localhost:7860 ..."
python app/ui.py
