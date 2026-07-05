"""
Extra static detectors used by the `endpoints` and `comments` pipeline
stages. Kept separate from patterns.py because they extract *candidates*
(API-looking paths, flagged comments) rather than fixed secret signatures.
"""
import re

# Looks for quoted string literals that resemble API paths, e.g. "/api/v2/users/:id"
ENDPOINT_RE = re.compile(r"""["'](/(?:api|v[0-9]+|internal|admin|graphql|rest|service)[a-zA-Z0-9_\-/{}.:]*)["']""")

# Matches // line comments and /* block */ comments (non-greedy, DOTALL for blocks)
LINE_COMMENT_RE = re.compile(r"//[^\n]*")
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

FLAGGED_KEYWORDS = re.compile(
    r"(?i)\b(TODO|FIXME|HACK|XXX|internal|debug|password|secret|api[_-]?key|"
    r"token|do not (?:commit|share|deploy)|temp(?:orary)? fix|remove before)\b"
)


def extract_endpoints(text: str, source: str) -> list[dict]:
    """Pull candidate internal/API endpoint paths out of a JS blob."""
    found = {}
    for m in ENDPOINT_RE.finditer(text):
        path = m.group(1)
        if path in found:
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        found[path] = {
            "type": "Discovered Endpoint",
            "match": path,
            "severity": "Informational",
            "line": line_no,
            "source": source,
            "detector": "endpoints",
        }
    return list(found.values())


def extract_comments(text: str, source: str) -> list[dict]:
    """Pull out comments that contain a flagged keyword (secrets, TODOs, debug notes)."""
    findings = []
    for pattern in (LINE_COMMENT_RE, BLOCK_COMMENT_RE):
        for m in pattern.finditer(text):
            comment = m.group(0)
            if not FLAGGED_KEYWORDS.search(comment):
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = comment.strip()
            if len(snippet) > 160:
                snippet = snippet[:160] + "..."
            findings.append({
                "type": "Flagged Comment",
                "match": snippet,
                "severity": "Low",
                "line": line_no,
                "source": source,
                "detector": "comments",
            })
    return findings
