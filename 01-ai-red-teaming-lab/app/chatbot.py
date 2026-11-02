"""Northwind Retail support chatbot: the target for the red-team lab."""
import os
from pathlib import Path

import requests
from fastapi import FastAPI
from pydantic import BaseModel

from app.guardrails import SAFE_REPLY, check_input, check_output

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.getenv("MODEL", "llama3.2")
SYSTEM_PROMPT = (Path(__file__).parent / "system_prompt.txt").read_text()

app = FastAPI(title="Northwind Support Bot")


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    reply: str
    blocked_by: str | None = None  # which guardrail fired, for the red-team logs


def ask_model(user_message: str) -> str:
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
    }
    resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
    resp.raise_for_status()
    return resp.json()["message"]["content"]


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    if reason := check_input(req.message):
        return ChatResponse(reply=SAFE_REPLY, blocked_by=reason)
    reply = ask_model(req.message)
    if reason := check_output(reply, SYSTEM_PROMPT):
        return ChatResponse(reply=SAFE_REPLY, blocked_by=reason)
    return ChatResponse(reply=reply)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": MODEL}
