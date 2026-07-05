"""Payment-provider API key/secret patterns."""
import re
from .severity import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

PATTERNS = {
    "Stripe Secret Key (live)": (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), SEVERITY_CRITICAL),
    "Stripe Restricted Key (live)": (re.compile(r"rk_live_[0-9a-zA-Z]{24,}"), SEVERITY_CRITICAL),
    "Stripe Publishable Key": (re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), SEVERITY_LOW),
    "Stripe Webhook Secret": (re.compile(r"whsec_[A-Za-z0-9]{32,}"), SEVERITY_HIGH),
    "Razorpay Key": (re.compile(r"rzp_live_[0-9A-Za-z]{14,}"), SEVERITY_HIGH),
    "Razorpay Secret": (re.compile(r"(?i)razorpay.{0,20}secret['\"]\s*[:=]\s*['\"][A-Za-z0-9]{20,}['\"]"), SEVERITY_CRITICAL),
    "PayPal Client Secret": (re.compile(r"(?i)paypal(.{0,20})?['\"][A-Za-z0-9_\-]{40,}['\"]"), SEVERITY_HIGH),
    "PayPal Braintree Access Token": (re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"), SEVERITY_CRITICAL),
    "Square Access Token": (re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"), SEVERITY_CRITICAL),
    "Square OAuth Secret": (re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}"), SEVERITY_CRITICAL),
    "Plaid Secret Key": (re.compile(r"(?i)plaid.{0,20}secret['\"]\s*[:=]\s*['\"][a-f0-9]{30}['\"]"), SEVERITY_CRITICAL),
    "Plaid Client ID": (re.compile(r"(?i)plaid.{0,20}client_?id['\"]\s*[:=]\s*['\"][a-f0-9]{24}['\"]"), SEVERITY_MEDIUM),
    "Braintree Private Key": (re.compile(r"(?i)braintree.{0,20}private['\"]\s*[:=]\s*['\"][a-f0-9]{32}['\"]"), SEVERITY_CRITICAL),
    "Adyen API Key": (re.compile(r"AQE[a-zA-Z0-9\-_]{80,}"), SEVERITY_CRITICAL),
    "Coinbase Commerce API Key": (re.compile(r"(?i)coinbase.{0,20}['\"][A-Za-z0-9\-]{40,}['\"]"), SEVERITY_HIGH),
    "Wise (TransferWise) API Token": (re.compile(r"(?i)wise.{0,20}token['\"]\s*[:=]\s*['\"][A-Za-z0-9_\-]{36,}['\"]"), SEVERITY_HIGH),
    "Chargebee Site API Key": (re.compile(r"(?i)chargebee.{0,20}['\"][a-z0-9]{20,}['\"]"), SEVERITY_HIGH),
    "Recurly API Key": (re.compile(r"(?i)recurly.{0,20}['\"][a-f0-9]{20,32}['\"]"), SEVERITY_HIGH),
    "Credit Card Number (PAN, Luhn-shaped)": (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"), SEVERITY_CRITICAL),
}
