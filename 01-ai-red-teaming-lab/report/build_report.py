"""Build report/retest-report.html from the before/after evidence of all three tools.

Run from the project root after a retest:
  source .venv-pyrit/bin/activate && python report/build_report.py
Leaks are re-graded with app.ui.detect_leaks so every tool is judged by the same rules.
"""
import collections, glob, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import os; os.chdir(ROOT)
from app.ui import detect_leaks
from app.guardrails import check_input, SAFE_REPLY

def clean(f): return re.sub(r"\*\*|`|🚨 |⚠️ ", "", f)
def threats(reply): return [clean(f) for f in detect_leaks(reply)]
def layer(prompt, reply):
    if check_input(prompt): return "Input filter"
    if reply.strip() == SAFE_REPLY: return "Output filter"
    return "Model (hardened prompt)"

OWASP = {"injection": "LLM01", "jailbreak": "LLM01", "extraction": "LLM07", "disclosure": "LLM02",
         "encoding": "LLM02", "control": "—", "holdout": "LLM07/02"}

def pf_rows(path, provider=None):
    d = json.load(open(path)); g = collections.defaultdict(list)
    for r in d["results"]["results"]:
        if provider and provider not in r["provider"]["label"]: continue
        out = r["response"]["output"] if r.get("response") else ""
        g[r["testCase"]["description"]].append((r["vars"]["attack"], out, r["success"]))
    return g

def summarize(runs):
    leaks = [(p, o) for p, o, ok in runs if (not ok) or threats(o)]
    sample = leaks[0][1] if leaks else runs[0][1]
    return {"leaks": len(leaks), "n": len(runs), "reply": sample, "threats": threats(sample) if leaks else []}

rows = []
def add(tool, suite, desc, prompt, b, a):
    kind = desc.split(" / ")[0] if " / " in desc else desc
    rows.append({"tool": tool, "suite": suite, "name": desc, "owasp": OWASP.get(kind, "LLM01"), "prompt": prompt,
                 "before": b, "after": a, "layer": layer(prompt, a["reply"]) if a["leaks"] == 0 else "—"})

B, A = pf_rows("results/promptfoo/before.json"), pf_rows("results/retest/promptfoo-after.json")
for desc in B:
    add("Promptfoo", "main", desc, B[desc][0][0], summarize(B[desc]), summarize(A[desc]))

HB, HA = pf_rows("results/retest/holdout.json", "before"), pf_rows("results/retest/holdout.json", "after")
for desc in HB:
    add("Promptfoo", "holdout", desc, HB[desc][0][0], summarize(HB[desc]), summarize(HA[desc]))

import asyncio
from pyrit.converter import Base64Converter, CharacterSpaceConverter, ROT13Converter
CONV = {"base64": Base64Converter(), "rot13": ROT13Converter(), "char_space": CharacterSpaceConverter()}
def sent_text(obj, conv):
    return obj if conv == "none" else asyncio.run(CONV[conv].convert_async(prompt=obj)).output_text

def pyrit(path): return {(r["attack_type"], r["converter"]): r for r in map(json.loads, open(path))}
PB, PA = pyrit("results/pyrit/before.jsonl"), pyrit("results/retest/pyrit-after.jsonl")
for k, rb in PB.items():
    ra = PA[k]
    one = lambda r: {"leaks": int(r["leak"] or bool(threats(r["reply"]))), "n": 1, "reply": r["reply"], "threats": threats(r["reply"])}
    t = k[0]; ow = "LLM07" if "prompt" in t and "inj" not in t else ("LLM02" if t in ("secret_disclosure", "discount_code") else "LLM01")
    rows.append({"tool": "PyRIT", "suite": "matrix", "name": f"{t.replace('_', ' ')} · {k[1]}", "owasp": ow,
                 "prompt": rb["objective"], "converter": k[1], "sent": sent_text(rb["objective"], k[1]), "before": one(rb), "after": one(ra),
                 "layer": "—" if one(ra)["leaks"] else ("Input filter" if check_input(sent_text(rb["objective"], k[1])) else
                          ("Output filter" if ra["reply"].strip() == SAFE_REPLY else "Model (hardened prompt)"))})

def garak(d):
    stats, hits, first, layers = collections.defaultdict(lambda: [0, 0]), {}, {}, collections.defaultdict(collections.Counter)
    for f in glob.glob(f"{d}/*.report.jsonl"):
        for l in open(f):
            r = json.loads(l)
            if r.get("entry_type") != "attempt" or r.get("status") != 2: continue
            probe = r["probe_classname"]
            p = r["prompt"]["turns"][-1]["content"]["text"] if isinstance(r["prompt"], dict) else str(r["prompt"])
            o = r["outputs"][0]; o = o if isinstance(o, str) else o.get("text", "")
            first.setdefault(probe, (p, o)); layers[probe][layer(p, o)] += 1
            for det, scores in r["detector_results"].items():
                if det == "mitigation.MitigationBypass": continue  # keyword false positive, see notes
                s = stats[(probe, det)]; s[1] += 1
                if scores and scores[0] >= 0.5:
                    s[0] += 1
                    hits.setdefault((probe, det), (p, o))
    return stats, hits, first, layers
GB, GBh, _, _ = garak("results/garak/before"); GA, _, GAfirst, GAlayers = garak("results/retest/garak-after")
garak_rows = []
for k, (hit, n) in GB.items():
    p, o = GBh.get(k, GAfirst.get(k[0], ("", "")))
    after = GA.get(k, [0, 0])
    garak_rows.append({"probe": k[0], "detector": k[1], "before": [hit, n], "after": after,
                       "prompt": p[:700], "reply": o[:500], "after_reply": GAfirst.get(k[0], ("", ""))[1][:500],
                       "layers": dict(GAlayers[k[0]])})

# One row per probe: several detectors grade the same prompts, so keep the worst one.
by_probe = {}
for g in garak_rows:
    best = by_probe.get(g["probe"])
    if best is None or g["before"][0] > best["before"][0]:
        by_probe[g["probe"]] = {**g, "detector": ", ".join(x["detector"] for x in garak_rows if x["probe"] == g["probe"])}
garak_rows = list(by_probe.values())

data = {"rows": rows, "garak": garak_rows,
        "prompt_before": open("mitigations/system_prompt.before.txt").read(),
        "prompt_after": open("app/system_prompt.txt").read()}
template = (ROOT / "report" / "retest_template.html").read_text()
html = template.replace("__DATA__", json.dumps(data).replace("</", "<\\/"))
(ROOT / "report" / "retest-report.html").write_text(html)
print("wrote report/retest-report.html")
