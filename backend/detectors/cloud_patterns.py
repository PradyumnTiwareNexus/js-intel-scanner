"""Cloud provider credential & storage-reference patterns."""
import re
from .severity import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

PATTERNS = {
    # --- AWS ---
    "AWS Access Key ID": (re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"), SEVERITY_CRITICAL),
    "AWS Secret Access Key": (re.compile(r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"), SEVERITY_CRITICAL),
    "AWS Session Token": (re.compile(r"(?i)aws(.{0,20})?session(.{0,20})?token(.{0,20})?['\"][A-Za-z0-9/+=]{100,}['\"]"), SEVERITY_HIGH),
    "AWS MWS Auth Token": (re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), SEVERITY_HIGH),
    "AWS ARN": (re.compile(r"arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:\d{12}:[a-zA-Z0-9\-_/:.]+"), SEVERITY_LOW),
    "AWS Cognito Identity Pool": (re.compile(r"[a-z]{2}-[a-z]+-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), SEVERITY_MEDIUM),

    # --- Google Cloud / Firebase ---
    "Google API Key": (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), SEVERITY_HIGH),
    "Google Cloud Service Account (JSON)": (re.compile(r'"type"\s*:\s*"service_account"'), SEVERITY_CRITICAL),
    "GCP Storage Bucket Ref": (re.compile(r"gs://[a-z0-9][a-z0-9._\-]{1,61}[a-z0-9]"), SEVERITY_MEDIUM),
    "Firebase DB URL": (re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), SEVERITY_MEDIUM),
    "Firebase Cloud Messaging Key": (re.compile(r"(?i)firebase.{0,20}key['\"]\s*[:=]\s*['\"]AAAA[A-Za-z0-9_\-:]{100,}['\"]"), SEVERITY_HIGH),
    "Google OAuth Client ID": (re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), SEVERITY_MEDIUM),
    "Google OAuth Client Secret": (re.compile(r"(?i)google.{0,20}secret['\"]\s*[:=]\s*['\"]GOCSPX-[A-Za-z0-9_\-]{28}['\"]"), SEVERITY_HIGH),
    "Google Cloud Storage HMAC Secret": (re.compile(r"(?i)GOOG[0-9A-Z]{20}"), SEVERITY_HIGH),

    # --- Azure ---
    "Azure Storage Account Key": (re.compile(r"(?i)AccountKey=[a-zA-Z0-9+/=]{88}"), SEVERITY_CRITICAL),
    "Azure Connection String": (re.compile(r"(?i)DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]+;AccountKey=[a-zA-Z0-9+/=]{88}"), SEVERITY_CRITICAL),
    "Azure SAS Token": (re.compile(r"(?i)sv=\d{4}-\d{2}-\d{2}&s[ri]=[a-z]+&sig=[A-Za-z0-9%]{20,}"), SEVERITY_HIGH),
    "Azure Client Secret": (re.compile(r"(?i)azure.{0,20}(client_?secret)['\"]\s*[:=]\s*['\"][A-Za-z0-9_\.\-~]{34,40}['\"]"), SEVERITY_CRITICAL),
    "Azure Blob Reference": (re.compile(r"https://[a-z0-9]+\.blob\.core\.windows\.net/[a-zA-Z0-9\-_./]+"), SEVERITY_MEDIUM),
    "Azure Function Key": (re.compile(r"(?i)code=[A-Za-z0-9_\-]{54,56}=="), SEVERITY_HIGH),
    "Azure DevOps PAT": (re.compile(r"(?i)azure.{0,20}devops.{0,20}['\"][a-z0-9]{52}['\"]"), SEVERITY_CRITICAL),

    # --- Other clouds / infra providers ---
    "DigitalOcean Token": (re.compile(r"do[a-z]{0,3}_v1_[a-f0-9]{64}"), SEVERITY_HIGH),
    "DigitalOcean OAuth Token": (re.compile(r"\b[A-Fa-f0-9]{64}\b(?=.{0,40}digitalocean)"), SEVERITY_MEDIUM),
    "Cloudflare API Key": (re.compile(r"(?i)cloudflare(.{0,20})?['\"][0-9a-f]{37}['\"]"), SEVERITY_HIGH),
    "Cloudflare API Token": (re.compile(r"(?i)cloudflare.{0,20}token['\"]\s*[:=]\s*['\"][A-Za-z0-9_\-]{40}['\"]"), SEVERITY_HIGH),
    "Cloudflare Global API Key": (re.compile(r"(?i)cf[_-]?global[_-]?api[_-]?key['\"]\s*[:=]\s*['\"][a-f0-9]{37}['\"]"), SEVERITY_CRITICAL),
    "Vercel Token": (re.compile(r"(?i)vercel(.{0,20})?['\"][A-Za-z0-9]{24}['\"]"), SEVERITY_HIGH),
    "Netlify Access Token": (re.compile(r"(?i)netlify.{0,20}['\"][A-Za-z0-9_\-]{40,45}['\"]"), SEVERITY_HIGH),
    "Heroku API Key": (re.compile(r"(?i)heroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"), SEVERITY_HIGH),
    "Linode API Token": (re.compile(r"(?i)linode.{0,20}['\"][a-f0-9]{64}['\"]"), SEVERITY_HIGH),
    "Alibaba Cloud AccessKey ID": (re.compile(r"LTAI[A-Za-z0-9]{12,20}"), SEVERITY_HIGH),
    "Alibaba Cloud AccessKey Secret": (re.compile(r"(?i)alibaba.{0,20}secret['\"]\s*[:=]\s*['\"][A-Za-z0-9]{30}['\"]"), SEVERITY_CRITICAL),
    "IBM Cloud API Key": (re.compile(r"(?i)ibm.{0,20}api.{0,20}key['\"]\s*[:=]\s*['\"][A-Za-z0-9_\-]{44}['\"]"), SEVERITY_HIGH),
    "Oracle Cloud Auth Token": (re.compile(r"(?i)oracle.{0,20}token['\"]\s*[:=]\s*['\"][A-Za-z0-9+/=]{20,}['\"]"), SEVERITY_MEDIUM),
    "Terraform Cloud Token": (re.compile(r"(?i)atlasv1\.[A-Za-z0-9\-_=]{60,90}"), SEVERITY_HIGH),

    # --- Storage bucket references (info-level recon value) ---
    "S3 Bucket URL": (re.compile(r"[a-z0-9.\-]+\.s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com|s3://[a-z0-9.\-]+"), SEVERITY_MEDIUM),
    "S3-Compatible Presigned URL": (re.compile(r"https?://[^\s'\"]+[?&]X-Amz-Signature=[A-Za-z0-9%]+"), SEVERITY_MEDIUM),
    "DigitalOcean Spaces URL": (re.compile(r"[a-z0-9\-]+\.[a-z0-9\-]+\.digitaloceanspaces\.com"), SEVERITY_LOW),
    "Backblaze B2 Key": (re.compile(r"(?i)b2.{0,20}key['\"]\s*[:=]\s*['\"][A-Za-z0-9]{31}['\"]"), SEVERITY_HIGH),
}
