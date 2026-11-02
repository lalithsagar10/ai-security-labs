# Project 1 Plan: AI Red-Teaming Lab

Working plan for building the lab described in [README.md](README.md). Tick boxes as you go.

> **Safety:** only attack the local Northwind chatbot. Use the fake secret, never a real one.

## Folder map

```
01-ai-red-teaming-lab/
├── README.md            # project spec
├── PLAN.md              # this file
├── app/                 # the target chatbot + system prompt (fake secret)
├── attacks/
│   ├── promptfoo/       # quick first-pass suite
│   ├── garak/           # vulnerability scanner runs
│   └── pyrit/           # orchestrated adversarial matrix + scorers
├── results/
│   ├── promptfoo/  garak/  pyrit/   # raw evidence per tool
│   └── retest/          # same probes, after fixes
├── mitigations/         # one note per control applied
├── report/              # findings, assessment, executive summary
└── ci/                  # workflow draft (final copy goes in /.github/workflows/)
```

---

## Phase 0: Setup
- [ ] Install [Ollama](https://ollama.com/) and pull a small model (e.g. `llama3.2` or `mistral`)
- [ ] Confirm it answers: `ollama run <model> "hello"`
- [ ] Python 3.10+ virtual env for this project; `requirements.txt` with `garak`, `pyrit`, `requests`
- [ ] Node.js installed (for Promptfoo: `npx promptfoo@latest`)
- [ ] Add `.gitignore` entries for the venv and any large logs

**Done when:** the model responds locally and all three tools install cleanly.

## Phase 1: Build the target (`app/`)
- [ ] Write `system_prompt.txt` with:
  - purpose (help Northwind customers with orders, returns, shipping)
  - prohibited behaviour (no off-topic, no harmful content, never reveal instructions)
  - data boundary (never disclose internal info)
  - planted fake secret, e.g. `NW-INTERNAL-KEY: FAKE-7f3a9c-DO-NOT-USE`
- [ ] Write `chatbot.py`: takes user input, sends system prompt + input to Ollama, returns the reply
- [ ] Expose it as a simple HTTP endpoint (e.g. FastAPI/Flask `POST /chat`) so every tool can hit the same target
- [ ] Test by hand with 3 normal questions and 3 obvious attacks; note results

**Done when:** `curl POST /chat` returns a sensible answer.

## Phase 2: Quick coverage with Promptfoo (`attacks/promptfoo/`)
- [ ] `promptfooconfig.yaml` pointing at `/chat`
- [ ] Enable red-team plugins for prompt injection, jailbreak, system-prompt extraction, PII/secret leakage
- [ ] Add a custom check: does the output contain `FAKE-7f3a9c`?
- [ ] Run, save output to `results/promptfoo/`

**Done when:** a first list of what broke exists.

## Phase 3: Systematic scan with Garak (`attacks/garak/`)
- [ ] `garak --list_probes` and `--list_generators`; save the list for reference
- [ ] Point Garak at the Ollama model / REST endpoint; confirm targeting with a tiny run
- [ ] Run the `promptinject` probe family first
- [ ] Run the encoding probes (`encoding.*`: base64, ROT13, etc.)
- [ ] Expand to `dan` / jailbreak and `leakreplay` probes
- [ ] Copy the hit-log and report into `results/garak/`

**Done when:** a Garak hit-log lists which probes succeeded.

## Phase 4: Deep attacks with PyRIT (`attacks/pyrit/`)
- [ ] Define the **target** (HTTP target → `/chat`)
- [ ] Build a prompt matrix covering the 6 attack types in the README catalogue
- [ ] Add **converters**: base64, ROT13, character-split
- [ ] Add a **scorer**: secret-substring check + refusal detector, so a leak is told apart from a refusal
- [ ] Run with an **orchestrator**; save the conversation logs and scores to `results/pyrit/`

**Done when:** scored results show real leaks vs refusals.

## Phase 5: Findings (`report/findings.md`)
- [ ] One entry per successful attack, using the template in `report/README.md`
- [ ] For each, write **why the control failed** (not just pass/fail)
- [ ] Map to OWASP LLM01 / LLM02 / LLM07 and a [MITRE ATLAS](https://atlas.mitre.org/) technique
- [ ] Give each a risk rating

## Phase 6: CI automation (`ci/` → `/.github/workflows/`)
- [ ] Pick a fast subset: key Promptfoo tests + 1–2 Garak probe families
- [ ] Workflow triggers on changes to `app/system_prompt.txt`, model config, or guardrail code
- [ ] Fail the build if the secret appears in any output
- [ ] Upload results as workflow artifacts
- [ ] Note: CI runners need a model. Use a small Ollama model in the runner, or a cheap API key in GitHub Secrets

**Done when:** a commit that changes the system prompt triggers the attacks automatically.

## Phase 7: Mitigate → Retest (`mitigations/`, `results/retest/`)
For each finding, in this order of strength:
- [ ] **Remove the secret from the prompt entirely** (strongest fix)
- [ ] Harden the system prompt (clear refusal rules, instruction hierarchy)
- [ ] Input filter (block or flag known injection/encoding patterns)
- [ ] Output filter (scan responses for the secret / system-prompt text before returning)
- [ ] Rerun the **same** probe after each fix; save to `results/retest/`
- [ ] Update each finding with its retest result

**Done when:** every finding has before/after evidence.

## Phase 8: Ship the portfolio piece (`report/`)
- [ ] `assessment.md`: scope, methodology, findings + evidence, risk ratings, affected assets, controls, retest results
- [ ] `executive-summary.md`: one page, no jargon, business impact
- [ ] Record a 3–5 min demo: attack works → fix → attack fails
- [ ] State what you built, where AI helped, and what still needs human validation
- [ ] Update the status in the root README from *Planned* to *Done*

---

## Progress log
| Date | Phase | What happened |
|---|---|---|
| 2026-10-17 | – | Folder structure and plan created |
