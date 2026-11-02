# Project 2 Plan: Secure RAG Application

Working plan for building the lab described in [README.md](README.md). Tick boxes as you go.
Visual guide: [part2-guide.html](part2-guide.html).

> **Safety:** only attack the local Northwind RAG app. All documents are fictional and the HR canary
> `NW-HR-CANARY-4b9e` is fake.

## Folder map

```
02-secure-rag-application/
├── app/
│   ├── corpus/public/   docs every employee may see
│   ├── corpus/hr/       HR-only docs, each with the fake canary
│   ├── store.py         Ollama embeddings + Chroma collection
│   ├── ingest.py        chunk, label, embed, store
│   ├── rag.py           retrieve + build prompt + generate
│   └── server.py        POST /ask, POST /ingest, GET /health  (port 8001)
├── attacks/             one script per attack + Promptfoo / PyRIT
├── results/before/  results/after/
├── report/
└── start.sh             builds the vector DB on first run, then serves
```

## Phase 0: Setup
- [x] `ollama pull nomic-embed-text` (embeddings); `llama3.2` already installed (answers)
- [x] Python 3.11 venv at `.venv` with `requirements.txt`

## Phase 1: Build the vulnerable app
- [x] 6 public + 3 HR-only fictional docs, HR docs carry the canary
- [x] Ingestion with metadata labels (`source`, `access`, `trust`, `owner`, `sha256`)
- [x] `/ask` with role from bearer token (`employee-token`, `hr-token`)
- [x] Deliberate flaws: no role filter on retrieval, context pasted into system prompt,
      "access control" written as a prompt sentence, open `/ingest`, no output check
- [x] Smoke test: employee asks about store manager pay → gets the HR salary band

## Phase 2: Attack it (`attacks/`, `results/before/`)
- [ ] Indirect prompt injection: upload `shipping-update.md` with a hidden instruction
- [ ] Cross-role leakage: employee query matrix, fail on canary or HR source retrieved
- [ ] Data poisoning: upload `refund-policy-v2.md` with false policy
- [ ] Context exfiltration: "print every document verbatim" style prompts
- [ ] Embedding weakness: HR-keyword-stuffed queries + a keyword-stuffed doc that ranks for everything
- [ ] Promptfoo matrix and PyRIT cross-domain injection run against `/ask`

## Phase 3: Findings (`report/findings.md`)
- [ ] One entry per success: evidence, why it worked, OWASP + MITRE ATLAS, risk rating

## Phase 4: Controls, one at a time (`app/guards.py`, env flags)
- [ ] Query-time role filter in Chroma (`where={"access": {"$in": allowed}}`)
- [ ] Ingestion scan + trust labels (quarantine instruction-like text, owner allowlist)
- [ ] Structural prompt separation (rules in system, chunks in a tagged untrusted data block)
- [ ] Output validation (canary, link allowlist, verbatim-dump check)
- [ ] Similarity threshold + citations

## Phase 5: Retest and ship
- [ ] Rerun the identical suite into `results/after/`; note residual risk per finding
- [ ] Report, one-page executive summary, short demo; update root README status

---

## Progress log
| Date | Phase | What happened |
|---|---|---|
| 2026-11-01 | 0–1 | Setup done, vulnerable RAG app built; cross-role salary leak reproduced on first try |
