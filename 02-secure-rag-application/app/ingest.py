"""Ingestion pipeline: split documents into chunks, label them, embed them, store them in Chroma.

Every chunk carries metadata:
  source  file name the chunk came from
  access  "public" (everyone) or "hr" (HR only)
  trust   "verified" for the curated corpus, "unverified" for anything uploaded at runtime
  owner   who supplied the document
  sha256  hash of the full document, for provenance

VULNERABLE BY DESIGN (Phase 1): ingest_document() accepts any text from anyone and stores it next
to the verified corpus. Nothing scans the content. The labels are written but nothing enforces them.

Run:  python -m app.ingest --reset
"""
import argparse
import hashlib
import re
from pathlib import Path

from app.store import DOC_PREFIX, embed, get_collection

CORPUS = Path(__file__).parent / "corpus"
CHUNK_CHARS = 700


def chunk(text: str) -> list[str]:
    """Split on markdown headings, then pack paragraphs into chunks of about CHUNK_CHARS."""
    sections = re.split(r"\n(?=#{1,3} )", text.strip())
    chunks, buf = [], ""
    for section in sections:
        for para in section.split("\n\n"):
            if buf and len(buf) + len(para) > CHUNK_CHARS:
                chunks.append(buf.strip())
                buf = ""
            buf += para + "\n\n"
    if buf.strip():
        chunks.append(buf.strip())
    return chunks


def ingest_document(name: str, text: str, access: str, trust: str, owner: str) -> int:
    """Chunk, embed and store one document. Returns the number of chunks stored."""
    collection = get_collection()
    digest = hashlib.sha256(text.encode()).hexdigest()
    pieces = chunk(text)
    collection.upsert(
        ids=[f"{name}#{i}" for i in range(len(pieces))],
        documents=pieces,
        embeddings=embed(pieces, DOC_PREFIX),
        metadatas=[
            {"source": name, "access": access, "trust": trust, "owner": owner, "sha256": digest}
            for _ in pieces
        ],
    )
    return len(pieces)


def ingest_corpus() -> None:
    for access in ("public", "hr"):
        for path in sorted((CORPUS / access).glob("*.md")):
            n = ingest_document(path.name, path.read_text(), access, "verified", "corpus")
            print(f"  {access:6} {path.name:28} {n} chunks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="delete the collection first")
    args = parser.parse_args()
    get_collection(reset=args.reset)
    print("Ingesting corpus...")
    ingest_corpus()
    print(f"Done: {get_collection().count()} chunks in the vector DB.")
