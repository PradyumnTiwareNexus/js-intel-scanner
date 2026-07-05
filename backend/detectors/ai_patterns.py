"""AI / LLM provider API key patterns."""
import re
from .severity import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_LOW

PATTERNS = {
    "OpenAI API Key (project)": (re.compile(r"sk-proj-[A-Za-z0-9_\-]{20,}"), SEVERITY_CRITICAL),
    "OpenAI API Key (legacy)": (re.compile(r"sk-[A-Za-z0-9]{20,50}T3BlbkFJ[A-Za-z0-9]{20,50}"), SEVERITY_CRITICAL),
    "OpenAI API Key (generic sk-)": (re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), SEVERITY_CRITICAL),
    "OpenAI Organization ID": (re.compile(r"org-[A-Za-z0-9]{24}"), SEVERITY_LOW),
    "Anthropic API Key": (re.compile(r"sk-ant-(api03-)?[A-Za-z0-9\-_]{20,}"), SEVERITY_CRITICAL),
    "Google Gemini API Key": (re.compile(r"AIzaSy[0-9A-Za-z\-_]{33}"), SEVERITY_HIGH),
    "HuggingFace Token": (re.compile(r"hf_[A-Za-z0-9]{34}"), SEVERITY_HIGH),
    "Cohere API Key": (re.compile(r"(?i)cohere.{0,20}['\"][A-Za-z0-9]{40}['\"]"), SEVERITY_HIGH),
    "Replicate API Token": (re.compile(r"r8_[A-Za-z0-9]{37}"), SEVERITY_HIGH),
    "Mistral API Key": (re.compile(r"(?i)mistral.{0,20}['\"][A-Za-z0-9]{32}['\"]"), SEVERITY_HIGH),
    "Groq API Key": (re.compile(r"gsk_[A-Za-z0-9]{52}"), SEVERITY_HIGH),
    "Perplexity API Key": (re.compile(r"pplx-[A-Za-z0-9]{40,}"), SEVERITY_HIGH),
    "ElevenLabs API Key": (re.compile(r"(?i)elevenlabs.{0,20}['\"][a-f0-9]{32}['\"]"), SEVERITY_HIGH),
    "Stability AI API Key": (re.compile(r"sk-[A-Za-z0-9]{48}(?=.{0,40}stability)"), SEVERITY_HIGH),
    "Together AI API Key": (re.compile(r"(?i)together.{0,20}['\"][a-f0-9]{64}['\"]"), SEVERITY_HIGH),
    "Azure OpenAI API Key": (re.compile(r"(?i)azure.{0,20}openai.{0,20}['\"][a-f0-9]{32}['\"]"), SEVERITY_CRITICAL),
    "LangChain / LangSmith API Key": (re.compile(r"ls__[A-Za-z0-9]{32,}"), SEVERITY_HIGH),
    "Pinecone API Key": (re.compile(r"(?i)pinecone.{0,20}['\"][a-f0-9\-]{36}['\"]"), SEVERITY_HIGH),
    "Weights & Biases API Key": (re.compile(r"(?i)wandb.{0,20}['\"][a-f0-9]{40}['\"]"), SEVERITY_HIGH),
}
