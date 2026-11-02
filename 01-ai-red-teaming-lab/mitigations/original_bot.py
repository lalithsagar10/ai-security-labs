"""The original, unprotected bot: old system prompt with the secrets, no guardrails.

Only for before/after comparisons such as attacks/promptfoo/holdout.yaml. Run from the project root:
  source .venv-pyrit/bin/activate && uvicorn mitigations.original_bot:app --port 8001
"""
from pathlib import Path

from fastapi import FastAPI

import app.chatbot as bot

bot.SYSTEM_PROMPT = (Path(__file__).parent / "system_prompt.before.txt").read_text()
app = FastAPI(title="Northwind Support Bot (original, unprotected)")


@app.post("/chat")
def chat(req: bot.ChatRequest) -> dict:
    return {"reply": bot.ask_model(req.message)}
