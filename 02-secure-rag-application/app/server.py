"""Northwind staff assistant API: the target for the Part 2 RAG attacks.

The role comes from the bearer token, decided server side (trust boundary 1). These are fake lab
tokens; a real app would use proper sign-in.

  Open http://localhost:8001 for the demo UI, or call the API directly:
  curl -s localhost:8001/ask -H 'Authorization: Bearer employee-token' \
       -H 'Content-Type: application/json' -d '{"question": "How long does shipping take?"}'
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from app.ingest import ingest_corpus, ingest_document
from app.rag import CHAT_MODEL, answer
from app.store import get_collection

TOKENS = {"employee-token": "employee", "hr-token": "hr"}
ROOT = Path(__file__).resolve().parent.parent
PAYLOADS = ROOT / "attacks" / "payloads"
LOG_FILE = ROOT / "results" / "ask-log.jsonl"

app = FastAPI(title="Northwind Staff Assistant (RAG)")


class AskRequest(BaseModel):
    question: str


class Source(BaseModel):
    id: str
    source: str
    access: str
    trust: str
    similarity: float


class AskResponse(BaseModel):
    answer: str
    role: str
    sources: list[Source]  # what was retrieved, logged as evidence for the attack runs


class IngestRequest(BaseModel):
    filename: str
    text: str


def role_from(authorization: str | None) -> str:
    token = (authorization or "").removeprefix("Bearer ").strip()
    if token not in TOKENS:
        raise HTTPException(status_code=401, detail="Unknown or missing token")
    return TOKENS[token]


def log(entry: dict) -> None:
    LOG_FILE.parent.mkdir(exist_ok=True)
    with LOG_FILE.open("a") as f:
        f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **entry}) + "\n")


@app.post("/ask", response_model=AskResponse)
def ask(req: AskRequest, authorization: str | None = Header(default=None)) -> AskResponse:
    role = role_from(authorization)
    result = answer(req.question, role)
    response = AskResponse(answer=result["answer"], role=role, sources=result["chunks"])
    log({"event": "ask", "question": req.question, **response.model_dump()})
    return response


@app.post("/ingest")
def ingest(req: IngestRequest, authorization: str | None = Header(default=None)) -> dict:
    # VULNERABLE BY DESIGN: any signed-in user can add documents, and nothing scans them.
    role = role_from(authorization)
    n = ingest_document(req.filename, req.text, access="public", trust="unverified", owner=role)
    log({"event": "ingest", "role": role, "filename": req.filename, "chunks": n})
    return {"stored": req.filename, "chunks": n}


@app.post("/reset")
def reset() -> dict:
    """Lab only: wipe uploaded documents and rebuild the index from the curated corpus."""
    get_collection(reset=True)
    ingest_corpus()
    log({"event": "reset"})
    return {"status": "reset", "chunks": get_collection().count()}


@app.get("/documents")
def documents() -> list[dict]:
    """One row per document in the index, so the UI can show what is loaded."""
    metas = get_collection().get(include=["metadatas"])["metadatas"]
    docs = {m["source"]: {k: m[k] for k in ("source", "access", "trust", "owner")} for m in metas}
    return sorted(docs.values(), key=lambda d: (d["trust"] != "unverified", d["access"], d["source"]))


@app.get("/payloads/{name}", response_class=PlainTextResponse)
def payload(name: str) -> str:
    # Look the name up in the folder listing instead of joining paths, so "../" can't escape it.
    files = {p.name: p for p in PAYLOADS.glob("*.md")}
    if name not in files:
        raise HTTPException(status_code=404, detail="No such payload")
    return files[name].read_text()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": CHAT_MODEL, "chunks": get_collection().count(), "defenses": "off"}


@app.get("/")
def ui() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")
