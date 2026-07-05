"""
Shannon entropy scanner — catches secrets that don't match a known
regex signature (custom API keys, random tokens, etc).
"""
import math
import re

TOKEN_RE = re.compile(r"['\"]([A-Za-z0-9+/_\-=]{20,100})['\"]")

# Common non-secret high-entropy noise to skip (minified var names, hashes of css, etc.)
NOISE_HINTS = re.compile(r"(?i)^(function|webpack|module\.exports|import |export )")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def scan_entropy(text: str, source: str, threshold: float = 4.3) -> list[dict]:
    findings = []
    for m in TOKEN_RE.finditer(text):
        token = m.group(1)
        if NOISE_HINTS.search(token):
            continue
        ent = shannon_entropy(token)
        if ent >= threshold:
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append({
                "type": "High-Entropy String",
                "match": f"{token[:6]}...{token[-4:]}",
                "severity": "Medium",
                "confidence_hint": round(min(ent / 6.0, 1.0) * 100, 1),
                "line": line_no,
                "source": source,
                "detector": "entropy",
            })
    return findings
