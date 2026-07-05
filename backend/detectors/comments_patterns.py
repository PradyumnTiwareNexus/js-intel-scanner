"""Patterns for interesting developer comments left in shipped JS."""
import re
from .severity import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

PATTERNS = {
    "Debug/TODO Marker": (re.compile(r"(?i)\b(TODO|FIXME|HACK|XXX)\b"), SEVERITY_INFO),
    "Sensitive Marker Comment": (re.compile(r"(?i)\b(DO NOT SHARE|DO NOT COMMIT|DO NOT DEPLOY|INTERNAL ONLY|CONFIDENTIAL)\b"), SEVERITY_MEDIUM),
    "Credentials Mentioned in Comment": (re.compile(r"(?i)//.*\b(password|secret|api[_-]?key|token)\b.*[:=]\s*\S+"), SEVERITY_HIGH),
    "Commented-Out Auth Header": (re.compile(r"(?i)//\s*.*authorization\s*[:=]\s*['\"]?(bearer|basic)\s+\S+"), SEVERITY_HIGH),
    "Disabled Security Check Comment": (re.compile(r"(?i)//.*\b(disable|bypass|skip)\b.*(auth|ssl|cert|verification|csrf)"), SEVERITY_MEDIUM),
    "Test Account Credential Comment": (re.compile(r"(?i)//.*\btest\s+(account|user|login)\b.*[:=]\s*\S+"), SEVERITY_LOW),
    "Backdoor/Bypass Marker": (re.compile(r"(?i)//.*\b(backdoor|bypass\s+auth|god\s?mode|master\s?key)\b"), SEVERITY_HIGH),
    "Author/Ownership Leak Comment": (re.compile(r"(?i)//\s*@author\s+[^\s]+@[^\s]+"), SEVERITY_LOW),
}
