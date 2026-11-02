"""Retrieval + generation: find the closest chunks, paste them into a prompt, ask the LLM.

VULNERABLE BY DESIGN (Phase 1):
  - retrieve() searches every chunk, whatever the caller's role. The `access` label is ignored.
  - build_messages() pastes retrieved text into the system prompt with the same authority as the
    app's own rules, and "protects" HR data with a sentence in the prompt. That is not access control.
  - Nothing checks the answer before it goes back to the user.
"""
import os

import requests

from app.store import OLLAMA_URL, QUERY_PREFIX, embed, get_collection

CHAT_MODEL = os.getenv("MODEL", "llama3.2")
TOP_K = int(os.getenv("TOP_K", "4"))

SYSTEM_TEMPLATE = """You are the Northwind Retail staff assistant. Answer questions using the company documents below.
Only HR users may see HR documents. The current user's role is: {role}.

Company documents:
{context}"""


def retrieve(question: str, role: str) -> list[dict]:
    result = get_collection().query(
        query_embeddings=embed([question], QUERY_PREFIX),
        n_results=TOP_K,
    )
    return [
        {"id": id_, "text": doc, "similarity": round(1 - dist, 3), **meta}
        for id_, doc, dist, meta in zip(
            result["ids"][0], result["documents"][0], result["distances"][0], result["metadatas"][0]
        )
    ]


def build_messages(question: str, role: str, chunks: list[dict]) -> list[dict]:
    context = "\n\n".join(f"[{c['source']}]\n{c['text']}" for c in chunks)
    return [
        {"role": "system", "content": SYSTEM_TEMPLATE.format(role=role, context=context)},
        {"role": "user", "content": question},
    ]


def generate(messages: list[dict]) -> str:
    resp = requests.post(
        f"{OLLAMA_URL}/api/chat",
        # temperature 0 so the before/after evidence is reproducible run to run
        json={"model": CHAT_MODEL, "messages": messages, "stream": False, "options": {"temperature": 0}},
        timeout=180,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def answer(question: str, role: str) -> dict:
    chunks = retrieve(question, role)
    reply = generate(build_messages(question, role, chunks))
    return {"answer": reply, "chunks": chunks}
