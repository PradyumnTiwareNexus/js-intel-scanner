"""PEM/PGP/SSH key blocks, PKCS formats, and blockchain/wallet patterns."""
import re
from .severity import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

PATTERNS = {
    # --- Key blocks ---
    "RSA Private Key Block": (re.compile(r"-----BEGIN RSA PRIVATE KEY-----"), SEVERITY_CRITICAL),
    "DSA Private Key Block": (re.compile(r"-----BEGIN DSA PRIVATE KEY-----"), SEVERITY_CRITICAL),
    "EC Private Key Block": (re.compile(r"-----BEGIN EC PRIVATE KEY-----"), SEVERITY_CRITICAL),
    "OpenSSH Private Key Block": (re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), SEVERITY_CRITICAL),
    "Generic PKCS#8 Private Key": (re.compile(r"-----BEGIN PRIVATE KEY-----"), SEVERITY_CRITICAL),
    "Encrypted PKCS#8 Private Key": (re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"), SEVERITY_HIGH),
    "PGP Private Key Block": (re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), SEVERITY_CRITICAL),
    "PGP Public Key Block": (re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----"), SEVERITY_LOW),
    "PGP Message": (re.compile(r"-----BEGIN PGP MESSAGE-----"), SEVERITY_MEDIUM),
    "SSH2 Public Key": (re.compile(r"---- BEGIN SSH2 PUBLIC KEY ----"), SEVERITY_LOW),
    "X.509 Certificate Block": (re.compile(r"-----BEGIN CERTIFICATE-----"), SEVERITY_LOW),
    "Certificate Request Block": (re.compile(r"-----BEGIN CERTIFICATE REQUEST-----"), SEVERITY_LOW),
    "OpenSSH Public Key (authorized_keys style)": (re.compile(r"ssh-(rsa|ed25519|dss) [A-Za-z0-9+/]{100,}={0,2}(\s+\S+@\S+)?"), SEVERITY_LOW),

    # --- Vault / secrets managers ---
    "HashiCorp Vault Token": (re.compile(r"\b[hs]\.[A-Za-z0-9]{24,90}\b"), SEVERITY_CRITICAL),
    "HashiCorp Vault Root Token (legacy)": (re.compile(r"\br\.[A-Za-z0-9]{24}\b"), SEVERITY_CRITICAL),
    "Kubernetes Secret (base64 data field)": (re.compile(r"(?i)kind:\s*Secret[\s\S]{0,300}data:\s*\n(\s+[\w.\-]+:\s*[A-Za-z0-9+/=]{8,}\n?)+"), SEVERITY_HIGH),
    "Kubernetes ServiceAccount Token": (re.compile(r"eyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9_\-\.]{100,}"), SEVERITY_CRITICAL),
    "Docker Config Auth (base64)": (re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'), SEVERITY_HIGH),
    "1Password Secret Key": (re.compile(r"A3-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}"), SEVERITY_CRITICAL),

    # --- Cryptocurrency ---
    "Bitcoin Wallet Address": (re.compile(r"\b(bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"), SEVERITY_LOW),
    "Ethereum Wallet Address": (re.compile(r"\b0x[a-fA-F0-9]{40}\b"), SEVERITY_LOW),
    "Ethereum Private Key": (re.compile(r"(?i)(private_?key|priv_?key)['\"]?\s*[:=]\s*['\"]?0x[a-fA-F0-9]{64}['\"]?"), SEVERITY_CRITICAL),
    "BIP39 Mnemonic Seed Phrase": (re.compile(r"(?i)(mnemonic|seed[_ ]?phrase)['\"]?\s*[:=]\s*['\"]([a-z]+\s+){11,23}[a-z]+['\"]"), SEVERITY_CRITICAL),
    "Litecoin Wallet Address": (re.compile(r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b"), SEVERITY_LOW),
    "Monero Wallet Address": (re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"), SEVERITY_LOW),
    "Ripple (XRP) Wallet Address": (re.compile(r"\br[0-9a-zA-Z]{24,34}\b"), SEVERITY_LOW),
    "Solana Wallet Address": (re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b(?=.{0,40}(solana|sol|phantom))"), SEVERITY_LOW),
    "Ethereum JSON-RPC Endpoint": (re.compile(r"https?://[^\s'\"]*(infura\.io|alchemy(api)?\.io|mainnet\.optimism\.io|polygon-rpc\.com)/v\d/[A-Za-z0-9_\-]+"), SEVERITY_MEDIUM),
    "Infura Project ID": (re.compile(r"(?i)infura.{0,20}['\"][a-f0-9]{32}['\"]"), SEVERITY_MEDIUM),
    "Alchemy API Key": (re.compile(r"(?i)alchemy.{0,20}['\"][A-Za-z0-9_\-]{32}['\"]"), SEVERITY_MEDIUM),
    "Blockchain RPC Endpoint (generic)": (re.compile(r"https?://[^\s'\"]+/(rpc|json-rpc)(/[A-Za-z0-9_\-]+)?"), SEVERITY_LOW),
    "Smart Contract Address Reference": (re.compile(r"(?i)contract(_?address)?['\"]?\s*[:=]\s*['\"]0x[a-fA-F0-9]{40}['\"]"), SEVERITY_LOW),
    "WalletConnect Project ID": (re.compile(r"(?i)walletconnect.{0,20}['\"][a-f0-9]{32}['\"]"), SEVERITY_MEDIUM),

    # --- Generic encoded blobs worth flagging in context ---
    "Base64-Encoded Secret Blob (labeled)": (re.compile(r"(?i)(secret|key|token|credential)['\"]?\s*[:=]\s*['\"][A-Za-z0-9+/]{40,}={0,2}['\"]"), SEVERITY_MEDIUM),
    "Hex-Encoded Secret Blob (labeled)": (re.compile(r"(?i)(secret|key|token)['\"]?\s*[:=]\s*['\"][a-fA-F0-9]{32,}['\"]"), SEVERITY_MEDIUM),
}
