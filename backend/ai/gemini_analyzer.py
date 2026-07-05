"""
Stage 2 AI analysis. Static detectors (regex/entropy/trufflehog/nuclei) run
first and produce candidate findings; Gemini is only used to CLASSIFY those
candidates in context (severity, false-positive likelihood, exploitability),
not to re-scan raw files blindly — keeps token cost down and improves signal.
"""
import json
import httpx as httpx_client
from backend.core.config import Config

GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

SYSTEM_PROMPT = """You are an elite Bug Bounty Security Researcher assistant.
You will be given a JS file's context and a list of candidate findings
already detected by static analysis (regex/entropy/trufflehog/nuclei).

For EACH candidate finding, return a JSON object with:
- id (index of the finding as given)
- severity: Critical | High | Medium | Low | Informational
- confidence: 0-100
- likely_false_positive: true/false
- reason: one sentence, why this matters (or why it's likely a false positive)
- exploitability: one short sentence
- bug_bounty_worthy: true/false
- remediation: one sentence

Ignore obvious placeholders like "YOUR_API_KEY_HERE", "xxxxxxxx", demo/test values.
Return ONLY a JSON array. No prose, no markdown fences.
"""


async def classify_findings(js_context: str, findings: list[dict], cfg: Config) -> list[dict]:
    """Send candidate findings (already redacted) to Gemini for triage."""
    if not cfg.gemini_api_key or not findings:
        return findings  # AI is optional enrichment, not a hard dependency

    payload_findings = [
        {"id": i, "type": f["type"], "match_preview": f.get("match", ""),
         "detector": f.get("detector", ""), "line": f.get("line")}
        for i, f in enumerate(findings)
    ]

    body = {
        "contents": [{
            "parts": [{
                "text": f"{SYSTEM_PROMPT}\n\nFILE CONTEXT (truncated):\n{js_context[:3000]}\n\n"
                        f"CANDIDATE FINDINGS:\n{json.dumps(payload_findings)}"
            }]
        }]
    }

    try:
        async with httpx_client.AsyncClient() as client:
            resp = await client.post(
                f"{GEMINI_ENDPOINT}?key={cfg.gemini_api_key}",
                json=body, timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
            ai_results = json.loads(text)
    except Exception as e:
        # AI enrichment failing must never break the pipeline
        for f in findings:
            f.setdefault("ai_note", f"AI classification unavailable: {e}")
        return findings

    by_id = {r["id"]: r for r in ai_results if "id" in r}
    for i, f in enumerate(findings):
        ai = by_id.get(i)
        if ai:
            f["ai_severity"] = ai.get("severity", f.get("severity"))
            f["confidence"] = ai.get("confidence")
            f["likely_false_positive"] = ai.get("likely_false_positive")
            f["reason"] = ai.get("reason")
            f["exploitability"] = ai.get("exploitability")
            f["bug_bounty_worthy"] = ai.get("bug_bounty_worthy")
            f["remediation"] = ai.get("remediation")
    return findings
