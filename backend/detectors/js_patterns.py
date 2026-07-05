"""JavaScript-artifact-specific patterns: source maps, obfuscation markers, sockets, CDNs."""
import re
from .severity import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

PATTERNS = {
    "Inline Source Map (data URI)": (re.compile(r"//#\s*sourceMappingURL=data:application/json;base64,[A-Za-z0-9+/=]{20,}"), SEVERITY_MEDIUM),
    "External Source Map Reference": (re.compile(r"//#\s*sourceMappingURL=(?!data:)([^\s]+\.map)"), SEVERITY_LOW),
    "Webpack Public Path Leak": (re.compile(r"__webpack_public_path__\s*=\s*['\"][^'\"]+['\"]"), SEVERITY_LOW),
    "WebSocket Endpoint": (re.compile(r"wss?://[^\s'\"]+"), SEVERITY_LOW),
    "CDN Endpoint Reference": (re.compile(r"https?://[a-z0-9\-]+\.(cloudfront\.net|akamaized\.net|fastly\.net|jsdelivr\.net|unpkg\.com)/[^\s'\"]*"), SEVERITY_INFO),
    "Obfuscated Eval/Packer Payload": (re.compile(r"eval\(function\(p,a,c,k,e,[dr]"), SEVERITY_MEDIUM),
    "Base64 Eval Execution": (re.compile(r"eval\(atob\(['\"][A-Za-z0-9+/=]{20,}['\"]\)\)"), SEVERITY_HIGH),
    "Dynamic Function Constructor (obfuscation smell)": (re.compile(r"new Function\(['\"][^'\"]{40,}['\"]\)"), SEVERITY_MEDIUM),
    "Hex-Escaped String Obfuscation": (re.compile(r"(\\x[0-9a-fA-F]{2}){10,}"), SEVERITY_LOW),
    "Unicode-Escaped String Obfuscation": (re.compile(r"(\\u[0-9a-fA-F]{4}){10,}"), SEVERITY_LOW),
    "Debugger Statement (left in prod build)": (re.compile(r"\bdebugger\s*;"), SEVERITY_INFO),
    "Console Debug Leak (sensitive-looking)": (re.compile(r"console\.(log|debug|warn)\([^)]*(token|secret|password|apikey|api_key)[^)]*\)", re.IGNORECASE), SEVERITY_LOW),
    "Environment Variable Dump Reference": (re.compile(r"process\.env\s*(\[|\.)[A-Za-z0-9_]*"), SEVERITY_INFO),
    "Analytics/Tracking Key (Segment)": (re.compile(r"(?i)segment.{0,20}(write_?key)['\"]\s*[:=]\s*['\"][A-Za-z0-9]{20,32}['\"]"), SEVERITY_MEDIUM),
    "Analytics/Tracking Key (Mixpanel)": (re.compile(r"(?i)mixpanel.{0,20}token['\"]\s*[:=]\s*['\"][a-f0-9]{32}['\"]"), SEVERITY_LOW),
    "Analytics/Tracking Key (Amplitude)": (re.compile(r"(?i)amplitude.{0,20}(api_?key)['\"]\s*[:=]\s*['\"][a-f0-9]{32}['\"]"), SEVERITY_LOW),
    "Google Analytics Measurement ID": (re.compile(r"\bG-[A-Z0-9]{10}\b"), SEVERITY_INFO),
    "Google Tag Manager ID": (re.compile(r"\bGTM-[A-Z0-9]{6,7}\b"), SEVERITY_INFO),
    "Sourcemap-Exposed Author Path (local disk leak)": (re.compile(r"(?:webpack://|file:///)[A-Za-z]:[\\/][^\s'\"]+|webpack:///(?:\./)?[^\s'\"]+"), SEVERITY_LOW),
    "Monitoring/APM Key (Bugsnag)": (re.compile(r"(?i)bugsnag.{0,20}(api_?key)['\"]\s*[:=]\s*['\"][a-f0-9]{32}['\"]"), SEVERITY_MEDIUM),
    "Monitoring/APM Key (Rollbar)": (re.compile(r"(?i)rollbar.{0,20}(access_?token)['\"]\s*[:=]\s*['\"][a-f0-9]{32}['\"]"), SEVERITY_MEDIUM),
}
