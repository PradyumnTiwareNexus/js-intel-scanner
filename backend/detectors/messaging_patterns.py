"""Messaging, chat, email, and webhook provider patterns."""
import re
from .severity import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

PATTERNS = {
    # --- SMS / voice ---
    "Twilio Account SID": (re.compile(r"AC[a-z0-9]{32}"), SEVERITY_HIGH),
    "Twilio Auth Token": (re.compile(r"(?i)twilio(.{0,20})?['\"][a-z0-9]{32}['\"]"), SEVERITY_HIGH),
    "Twilio API Key": (re.compile(r"SK[a-z0-9]{32}"), SEVERITY_HIGH),
    "Vonage/Nexmo API Secret": (re.compile(r"(?i)nexmo.{0,20}secret['\"]\s*[:=]\s*['\"][a-z0-9]{16}['\"]"), SEVERITY_HIGH),
    "Plivo Auth Token": (re.compile(r"(?i)plivo.{0,20}['\"][A-Za-z0-9]{40}['\"]"), SEVERITY_HIGH),

    # --- Email ---
    "SendGrid API Key": (re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), SEVERITY_HIGH),
    "Mailgun API Key": (re.compile(r"key-[0-9a-zA-Z]{32}"), SEVERITY_HIGH),
    "Mailgun Signing Key": (re.compile(r"(?i)mailgun.{0,20}signing.{0,20}['\"][0-9a-f\-]{32,}['\"]"), SEVERITY_HIGH),
    "Mailchimp API Key": (re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"), SEVERITY_HIGH),
    "Postmark Server Token": (re.compile(r"(?i)postmark.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"), SEVERITY_HIGH),
    "SMTP Credentials in URL": (re.compile(r"smtps?://[^:\s]+:[^@\s]+@[^\s'\"]+"), SEVERITY_CRITICAL),
    "IMAP/POP3 Credentials in URL": (re.compile(r"(imap|pop3)s?://[^:\s]+:[^@\s]+@[^\s'\"]+"), SEVERITY_CRITICAL),
    "AWS SES SMTP Credentials": (re.compile(r"(?i)ses.{0,20}smtp.{0,20}['\"][A-Za-z0-9+/]{40,}['\"]"), SEVERITY_HIGH),

    # --- Chat / collaboration ---
    "Slack Token": (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,72}"), SEVERITY_HIGH),
    "Slack Webhook URL": (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"), SEVERITY_MEDIUM),
    "Slack App Config Token": (re.compile(r"xapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[a-f0-9]{64}"), SEVERITY_HIGH),
    "Discord Bot Token": (re.compile(r"[MN][A-Za-z0-9_\-]{23,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}"), SEVERITY_CRITICAL),
    "Discord Webhook URL": (re.compile(r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"), SEVERITY_MEDIUM),
    "Telegram Bot Token": (re.compile(r"\d{9,10}:[A-Za-z0-9_-]{35}"), SEVERITY_HIGH),
    "Microsoft Teams Webhook URL": (re.compile(r"https://[a-z0-9\-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9\-@/]+"), SEVERITY_MEDIUM),
    "Zoom JWT API Key/Secret": (re.compile(r"(?i)zoom.{0,20}(api_?key|api_?secret)['\"]\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"), SEVERITY_HIGH),
    "Intercom Access Token": (re.compile(r"(?i)intercom.{0,20}['\"][A-Za-z0-9=_\-]{40,}['\"]"), SEVERITY_HIGH),
    "Zendesk API Token": (re.compile(r"(?i)zendesk.{0,20}token['\"]\s*[:=]\s*['\"][A-Za-z0-9]{40}['\"]"), SEVERITY_HIGH),
    "Generic Incoming Webhook URL": (re.compile(r"https?://[^\s'\"]*/webhooks?/[A-Za-z0-9\-_/]{10,}"), SEVERITY_LOW),
}
