"""Hash / digest format patterns — useful recon signal, rarely secrets by themselves."""
import re
from .severity import SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

PATTERNS = {
    "MD5 Hash": (re.compile(r"\b[a-f0-9]{32}\b"), SEVERITY_INFO),
    "SHA1 Hash": (re.compile(r"\b[a-f0-9]{40}\b"), SEVERITY_INFO),
    "SHA256 Hash": (re.compile(r"\b[a-f0-9]{64}\b"), SEVERITY_INFO),
    "SHA512 Hash": (re.compile(r"\b[a-f0-9]{128}\b"), SEVERITY_INFO),
    "bcrypt Hash": (re.compile(r"\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}"), SEVERITY_MEDIUM),
    "Argon2 Hash": (re.compile(r"\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+"), SEVERITY_MEDIUM),
    "PBKDF2 Hash": (re.compile(r"\$pbkdf2-sha\d+\$\d+\$[A-Za-z0-9./+]+\$[A-Za-z0-9./+]+"), SEVERITY_MEDIUM),
    "scrypt Hash": (re.compile(r"\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+"), SEVERITY_MEDIUM),
    "NTLM Hash (labeled)": (re.compile(r"(?i)ntlm['\"]?\s*[:=]\s*['\"]?[a-f0-9]{32}['\"]?"), SEVERITY_MEDIUM),
    "CRC32 Checksum (labeled)": (re.compile(r"(?i)crc32['\"]?\s*[:=]\s*['\"]?[a-f0-9]{8}['\"]?"), SEVERITY_LOW),
}
