"""
Regex pattern library for secret/PII/endpoint detection.

Signatures are split by category into sibling modules in this same
backend/detectors/ directory, so the library can grow past a few hundred
patterns without becoming one unmanageable file:

    cloud_patterns.py       AWS / GCP / Azure / other cloud & storage
    auth_patterns.py        OAuth, JWT, sessions, generic bearer/basic auth
    crypto_patterns.py      PEM/PGP/SSH key blocks, vaults, crypto wallets
    database_patterns.py    DB connection strings (Mongo/Postgres/Redis/...)
    payment_patterns.py     Stripe/PayPal/Square/Razorpay/...
    messaging_patterns.py   Slack/Discord/Telegram/Twilio/SMTP/...
    devops_patterns.py      GitHub/GitLab/CI/Docker/K8s/observability
    ai_patterns.py          OpenAI/Anthropic/Gemini/HuggingFace/...
    pii_patterns.py         Emails, phone numbers, IPs, SSNs, UUIDs
    hashes_patterns.py      MD5/SHA*/bcrypt/argon2/... digest formats
    js_patterns.py          Source maps, obfuscation, sockets, CDNs
    endpoints_patterns.py   REST/GraphQL/admin/debug endpoint discovery
    comments_patterns.py    Sensitive/flagged developer comments
    saas_patterns.py        Shopify/Contentful/Algolia/Notion/HubSpot/...

Every module exposes a module-level `PATTERNS = {name: (compiled_re, severity)}`
dict, sourced from the shared `severity.py` constants. This file merges them
all into one `PATTERNS` dict and keeps the exact same public API the rest of
the codebase (and the test suite) already depends on:
`PATTERNS`, `scan_text()`, and the `SEVERITY_*` constants re-exported below.

Adding a new signature therefore never means touching this file — drop it
into the right category module (or add a new `*_patterns.py` module and
register it in _MODULES below).

Note: `entropy.py` (Shannon-entropy scanning) and `extras.py` (endpoint/
comment candidate extraction used by the `endpoints`/`comments` pipeline
stages) are separate, complementary detectors and are intentionally not
merged into this regex table — see those modules directly.
"""
from backend.detectors.severity import (
    SEVERITY_CRITICAL,  # noqa: F401 — re-exported for backward compatibility
    SEVERITY_HIGH,  # noqa: F401
    SEVERITY_MEDIUM,  # noqa: F401
    SEVERITY_LOW,  # noqa: F401
    SEVERITY_INFO,  # noqa: F401
)
from backend.detectors import (
    cloud_patterns,
    auth_patterns,
    crypto_patterns,
    database_patterns,
    payment_patterns,
    messaging_patterns,
    devops_patterns,
    ai_patterns,
    pii_patterns,
    hashes_patterns,
    js_patterns,
    endpoints_patterns,
    comments_patterns,
    saas_patterns,
)

_MODULES = (
    cloud_patterns,
    auth_patterns,
    crypto_patterns,
    database_patterns,
    payment_patterns,
    messaging_patterns,
    devops_patterns,
    ai_patterns,
    pii_patterns,
    hashes_patterns,
    js_patterns,
    endpoints_patterns,
    comments_patterns,
    saas_patterns,
)

PATTERNS: dict = {}
for _mod in _MODULES:
    for _name, _spec in _mod.PATTERNS.items():
        if _name in PATTERNS:
            # Two category modules defined the same finding name — keep the
            # first and raise instead of silently overwriting, so a
            # copy-paste collision surfaces immediately in tests/CI.
            raise ValueError(
                f"Duplicate pattern name '{_name}' in {_mod.__name__} "
                f"(already defined earlier in the merge order)"
            )
        PATTERNS[_name] = _spec


def scan_text(text: str, source: str) -> list[dict]:
    """Run all regex patterns against a blob of text, return findings."""
    findings = []
    for name, (pattern, severity) in PATTERNS.items():
        for m in pattern.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append({
                "type": name,
                "match": _redact(m.group(0)),
                "severity": severity,
                "line": line_no,
                "source": source,
                "detector": "regex",
            })
    return findings


def _redact(value: str, keep: int = 6) -> str:
    """Never store full secret in plaintext reports — keep a short prefix."""
    if len(value) <= keep * 2:
        return value[:keep] + "..." if len(value) > keep else value
    return f"{value[:keep]}...{value[-4:]}"
