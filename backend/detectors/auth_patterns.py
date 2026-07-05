"""OAuth, session, JWT, and generic bearer/auth-header patterns."""
import re
from .severity import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

PATTERNS = {
    "JWT": (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}"), SEVERITY_MEDIUM),
    "Bearer Token": (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.=]{20,}"), SEVERITY_MEDIUM),
    "Basic Auth Header": (re.compile(r"(?i)authorization['\"]?\s*[:=]\s*['\"]?basic\s+[A-Za-z0-9+/=]{10,}"), SEVERITY_MEDIUM),
    "Basic Auth in URL": (re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'\"/:@]+:[^\s'\"/:@]+@[^\s'\"]+"), SEVERITY_HIGH),
    "OAuth Access Token (generic)": (re.compile(r"(?i)access_?token['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{20,}['\"]"), SEVERITY_HIGH),
    "OAuth Refresh Token (generic)": (re.compile(r"(?i)refresh_?token['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{20,}['\"]"), SEVERITY_HIGH),
    "Client Secret (generic)": (re.compile(r"(?i)client_?secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]"), SEVERITY_HIGH),
    "Client ID (generic, low-signal)": (re.compile(r"(?i)client_?id['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]"), SEVERITY_LOW),
    "Session ID / Cookie Token": (re.compile(r"(?i)(session_?id|sessid|sess_token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), SEVERITY_MEDIUM),
    "CSRF Token (hardcoded)": (re.compile(r"(?i)csrf_?token['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), SEVERITY_LOW),
    "API Key (generic pattern)": (re.compile(r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,64}['\"]"), SEVERITY_MEDIUM),
    "Secret Key (generic pattern)": (re.compile(r"(?i)secret[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-/+]{16,64}['\"]"), SEVERITY_MEDIUM),
    "Hardcoded Password": (re.compile(r"(?i)\bpassword['\"]?\s*[:=]\s*['\"](?!(\{\{|\$\{|change.?me|your_?password|xxxx))[^\s'\"]{6,64}['\"]"), SEVERITY_HIGH),
    "Hardcoded Username + Password Pair": (re.compile(r"(?i)username['\"]?\s*[:=]\s*['\"][^'\"]{2,32}['\"].{0,60}password['\"]?\s*[:=]\s*['\"][^'\"]{4,64}['\"]"), SEVERITY_HIGH),
    "SAML Assertion": (re.compile(r"<saml2?:Assertion[^>]*>"), SEVERITY_MEDIUM),
    "Auth0 Client Secret": (re.compile(r"(?i)auth0.{0,20}secret['\"]\s*[:=]\s*['\"][A-Za-z0-9_\-]{48,64}['\"]"), SEVERITY_CRITICAL),
    "Auth0 Management API Token": (re.compile(r"(?i)auth0.{0,20}token['\"]\s*[:=]\s*['\"]eyJ[A-Za-z0-9_\-\.]{50,}['\"]"), SEVERITY_HIGH),
    "Okta API Token": (re.compile(r"(?i)00[a-zA-Z0-9_\-]{40}"), SEVERITY_HIGH),
    "JWT Signing Secret (config)": (re.compile(r"(?i)jwt.{0,20}secret['\"]\s*[:=]\s*['\"][A-Za-z0-9_\-!@#$%^&*]{8,64}['\"]"), SEVERITY_CRITICAL),
    "Firebase Auth Custom Token": (re.compile(r"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), SEVERITY_HIGH),
    "NPM Auth Token": (re.compile(r"(?i)_authToken\s*=\s*[A-Za-z0-9\-_]{36,}"), SEVERITY_HIGH),
    "PyPI Upload Token": (re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"), SEVERITY_HIGH),
}
