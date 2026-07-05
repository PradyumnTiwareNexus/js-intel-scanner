"""PII and generic identifier patterns (emails, phones, IPs, UUIDs)."""
import re
from .severity import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

PATTERNS = {
    "Email Address": (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), SEVERITY_INFO),
    "Phone Number (E.164-ish)": (re.compile(r"(?<![\w])\+[1-9]\d{7,14}(?![\w])"), SEVERITY_LOW),
    "US Social Security Number": (re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), SEVERITY_CRITICAL),
    "UUID / GUID": (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), SEVERITY_INFO),
    "Public IPv4 Address": (re.compile(r"\b(?!10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)(\d{1,3}\.){3}\d{1,3}\b"), SEVERITY_LOW),
    "Internal IP (RFC1918)": (re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"), SEVERITY_LOW),
    "IPv6 Address": (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"), SEVERITY_LOW),
    "Internal Hostname (.local/.internal/.corp)": (re.compile(r"\b[a-z0-9][a-z0-9\-]*\.(internal|corp|local|lan|intra)\b"), SEVERITY_LOW),
    "MAC Address": (re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), SEVERITY_INFO),
    "IBAN": (re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"), SEVERITY_HIGH),
    "US Passport Number (labeled)": (re.compile(r"(?i)passport.{0,10}(no|number|#)?['\"]?\s*[:=]\s*['\"]?[0-9A-Z]{6,9}['\"]?"), SEVERITY_HIGH),
    "Date of Birth (labeled)": (re.compile(r"(?i)(date_?of_?birth|dob)['\"]?\s*[:=]\s*['\"]?\d{4}-\d{2}-\d{2}"), SEVERITY_MEDIUM),
}
