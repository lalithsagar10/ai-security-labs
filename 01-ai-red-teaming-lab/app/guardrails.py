"""Input and output guardrails for the Northwind bot.

Input filter:  blocks known injection / extraction / jailbreak patterns, also after
               decoding base64 and ROT13 that the attacker may have wrapped them in.
Output filter: blocks replies that contain secret-shaped strings or verbatim lines of
               the system prompt, in plain, base64, ROT13, reversed or spaced form.
Both return a reason string when they block, or None to let the message through.
"""
import base64
import codecs
import re

SAFE_REPLY = "I can't help with that, but I'm happy to help with your Northwind order, shipping, or returns."

INJECTION_PATTERNS = [
    r"\b(ignore|disregard|forget|override)\b.{0,40}\b(instructions?|rules|prompt|directions)\b",
    r"\b(system|developer|maintenance|debug|admin)\s+(override|mode)\b",
    r"\b(system prompt|your (instructions|configuration|rules|prompt))\b",
    r"\brepeat (everything|all|the text) above\b",
    r"\b(internal[_ ]api[_ ]key|api key|override code|discount code staff|staff (discount )?code)\b",
    r"\byou are (now )?dan\b|\bdo anything now\b|\bno (rules|restrictions|filters)\b|\bjailbr(oken|eak)\b",
    r"\bjust (print|say|output)\b",
]

# Secret-shaped strings. The real values were removed from the prompt; this is the backstop
# in case a secret is ever pasted back in or the model hallucinates one in the same format.
SECRET_PATTERNS = [
    r"NW-[A-Z]+-[0-9a-f]{6}",
    r"7f3a9c",
    r"STAFF-ONLY-\d+",
]


def _decoded_forms(text: str) -> list[str]:
    """The text itself plus ROT13, reversed, de-spaced and base64-decoded versions of it."""
    forms = [text, codecs.encode(text, "rot13"), text[::-1], re.sub(r"[\s.,]", "", text)]
    for token in re.findall(r"[A-Za-z0-9+/=]{12,}", text):
        try:
            forms.append(base64.b64decode(token + "=" * (-len(token) % 4)).decode("utf-8", "ignore"))
        except Exception:
            pass
    return forms


def check_input(message: str) -> str | None:
    for form in _decoded_forms(message):
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, form, re.I):
                return f"input: matched injection pattern {pattern!r}"
    return None


def check_output(reply: str, system_prompt: str) -> str | None:
    prompt_lines = [ln.strip("- ").strip() for ln in system_prompt.splitlines() if len(ln.strip()) > 30]
    for form in _decoded_forms(reply):
        for pattern in SECRET_PATTERNS:
            if re.search(pattern, form, re.I):
                return f"output: secret-shaped string {pattern!r}"
        lowered = form.lower()
        for line in prompt_lines:
            if line.lower()[:40] in lowered:
                return "output: verbatim system-prompt text"
    return None
