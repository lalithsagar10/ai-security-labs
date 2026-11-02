"""Shared plumbing: Ollama embeddings and the Chroma collection."""
import os
from pathlib import Path

import chromadb
import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")
CHROMA_PATH = Path(__file__).parent.parent / "data" / "chroma"
COLLECTION = "northwind-docs"

# nomic-embed-text is trained with these task prefixes; using them improves retrieval quality.
DOC_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "


def embed(texts: list[str], prefix: str) -> list[list[float]]:
    resp = requests.post(
        f"{OLLAMA_URL}/api/embed",
        json={"model": EMBED_MODEL, "input": [prefix + t for t in texts]},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["embeddings"]


def get_collection(reset: bool = False):
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    if reset and COLLECTION in [c.name for c in client.list_collections()]:
        client.delete_collection(COLLECTION)
    return client.get_or_create_collection(COLLECTION, configuration={"hnsw": {"space": "cosine"}})
