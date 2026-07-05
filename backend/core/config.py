"""
Config manager: handles tool paths, thresholds, API keys, and the
config-driven pipeline (stage order, per-stage settings, named profiles).
No hard-coded binary paths — everything resolved via PATH auto-detect
or explicit override in configs/config.yaml.
"""
import copy
import logging
import shutil
import subprocess
import yaml
from pathlib import Path
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("config")

CONFIG_DIR = Path(__file__).resolve().parents[2] / "configs"
CONFIG_FILE = CONFIG_DIR / "config.yaml"

# Tools this platform depends on. Add more here if needed.
REQUIRED_TOOLS = [
    "subfinder", "assetfinder", "amass",
    "httpx", "katana", "gau", "waybackurls",
    "hakrawler", "gospider",
    "trufflehog", "nuclei",
]

DEFAULT_PIPELINE = [
    "subfinder", "assetfinder", "amass", "deduplicate", "httpx",
    "katana", "hakrawler", "gospider", "gau", "waybackurls",
    "robots", "sitemap", "jsfinder", "verify_js", "download_js",
    "regex", "entropy", "endpoints", "comments",
    "trufflehog", "nuclei", "gemini", "report",
]

DEFAULT_STAGES = {
    "subfinder":   {"enabled": True, "timeout": 30,  "retries": 2, "workers": 10},
    "assetfinder": {"enabled": True, "timeout": 30,  "retries": 2, "workers": 10},
    "amass":       {"enabled": True, "timeout": 180, "retries": 1, "workers": 1},
    "deduplicate": {"enabled": True},
    "httpx":       {"enabled": True, "timeout": 20,  "retries": 2, "workers": 50},
    "katana":      {"enabled": True, "timeout": 120, "retries": 2, "workers": 5},
    "hakrawler":   {"enabled": True, "timeout": 120, "retries": 1, "workers": 3},
    "gospider":    {"enabled": True, "timeout": 180, "retries": 1, "workers": 3},
    "gau":         {"enabled": True, "timeout": 60,  "retries": 2, "workers": 5},
    "waybackurls": {"enabled": True, "timeout": 60,  "retries": 2, "workers": 5},
    "robots":      {"enabled": True, "timeout": 15,  "retries": 1, "workers": 1},
    "sitemap":     {"enabled": True, "timeout": 15,  "retries": 1, "workers": 1},
    "jsfinder":    {"enabled": True},
    "verify_js":   {"enabled": True, "timeout": 15,  "retries": 1, "workers": 40},
    "download_js": {"enabled": True, "timeout": 15,  "retries": 1, "workers": 40},
    "regex":       {"enabled": True},
    "entropy":     {"enabled": True},
    "endpoints":   {"enabled": True},
    "comments":    {"enabled": True},
    "trufflehog":  {"enabled": True, "timeout": 300, "retries": 1, "workers": 1},
    "nuclei":      {"enabled": True, "timeout": 300, "retries": 1, "workers": 1},
    "gemini":      {"enabled": True, "timeout": 30,  "retries": 1, "workers": 1},
    "report":      {"enabled": True},
}

DEFAULT_PROFILES = {
    "fast": {
        "disable": ["amass", "hakrawler", "gospider", "nuclei", "trufflehog"],
        "workers": {"katana": 3, "httpx": 50},
    },
    "balanced": {"disable": [], "workers": {}},
    "deep": {
        "disable": [],
        "workers": {"katana": 10, "hakrawler": 5, "gospider": 5, "nuclei": 10},
    },
    "stealth": {
        "disable": ["amass", "gospider"],
        "rate_limit": 10,
        "workers": {"katana": 1, "httpx": 5},
    },
}

DEFAULTS = {
    "tool_paths": {},          # tool_name -> resolved absolute path
    "gemini_api_key": "",
    "threads": 40,
    "timeout": 15,
    "retries": 2,
    "proxy": "",
    "rate_limit": 150,         # requests/sec ceiling passed to httpx etc.
    "export_folder": "exports",
    "theme": "dark",
    "active_profile": "balanced",
    "pipeline": DEFAULT_PIPELINE,
    "stages": DEFAULT_STAGES,
    "profiles": DEFAULT_PROFILES,
}


@dataclass
class Config:
    tool_paths: dict = field(default_factory=dict)
    gemini_api_key: str = ""
    threads: int = 40
    timeout: int = 15
    retries: int = 2
    proxy: str = ""
    rate_limit: int = 150
    export_folder: str = "exports"
    theme: str = "dark"
    active_profile: str = "balanced"
    pipeline: list = field(default_factory=lambda: list(DEFAULT_PIPELINE))
    stages: dict = field(default_factory=lambda: copy.deepcopy(DEFAULT_STAGES))
    profiles: dict = field(default_factory=lambda: copy.deepcopy(DEFAULT_PROFILES))

    @classmethod
    def load(cls) -> "Config":
        if CONFIG_FILE.exists():
            data = yaml.safe_load(CONFIG_FILE.read_text()) or {}
        else:
            data = {}
        merged = {**DEFAULTS, **data}
        # Only keep dataclass fields — unknown top-level keys in a hand-edited
        # config.yaml are ignored rather than crashing the whole platform.
        field_names = set(cls.__dataclass_fields__)
        merged = {k: v for k, v in merged.items() if k in field_names}
        return cls(**merged)

    def save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(yaml.safe_dump(asdict(self), sort_keys=False))

    def get_tool(self, name: str) -> str | None:
        """Return configured or auto-detected path for a tool binary.

        `httpx` is a name collision: pip's Python HTTP client also installs
        an `httpx` CLI, and if it's earlier on PATH than ProjectDiscovery's
        recon tool of the same name, every httpx-dependent stage silently
        breaks (wrong flags, non-zero exit). We verify the binary before
        trusting it, and never cache a wrong match.
        """
        if name in self.tool_paths and self.tool_paths[name]:
            cached = self.tool_paths[name]
            if name != "httpx" or _is_projectdiscovery_httpx(cached):
                return cached
            logger.warning("Cached httpx path %s failed validation, re-resolving", cached)
            self.tool_paths[name] = ""

        found = shutil.which(name)
        if not found:
            return None

        if name == "httpx" and not _is_projectdiscovery_httpx(found):
            logger.warning(
                "Found '%s' at %s but it is the Python `httpx` CLI, not "
                "ProjectDiscovery's httpx recon tool — treating as missing. "
                "Install https://github.com/projectdiscovery/httpx and make "
                "sure it comes first on PATH, or set tool_paths.httpx in "
                "config.yaml to its full path.", name, found,
            )
            return None

        self.tool_paths[name] = found
        return found

    def stage_cfg(self, name: str) -> dict:
        """Effective settings for one stage: base config merged with the
        active profile's overrides (disable list + worker/rate overrides)."""
        base = dict(self.stages.get(name, {"enabled": True}))
        profile = self.profiles.get(self.active_profile, {})
        if name in profile.get("disable", []):
            base["enabled"] = False
        worker_override = profile.get("workers", {}).get(name)
        if worker_override is not None:
            base["workers"] = worker_override
        return base

    def effective_pipeline(self) -> list[str]:
        """Stage names in configured order, filtered to those enabled after
        applying the active profile. Unknown stage names are kept — the
        orchestrator's registry lookup (built-ins + plugins) resolves them,
        and reports 'unknown stage' rather than crashing if truly missing."""
        return [name for name in self.pipeline if self.stage_cfg(name).get("enabled", True)]


def _is_projectdiscovery_httpx(path: str) -> bool:
    """ProjectDiscovery's httpx supports `-version` and exits 0 with a
    banner. The Python `httpx` CLI (Click-based) rejects unknown flags with
    a "Usage: httpx [OPTIONS] URL" error and non-zero exit — that's the
    signature we reject on."""
    try:
        proc = subprocess.run(
            [path, "-version"], capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    output = (proc.stdout + proc.stderr).lower()
    if proc.returncode != 0:
        return False
    if "usage: httpx" in output or "no such option" in output:
        return False
    return True


def detect_all_tools(cfg: Config) -> dict:
    """Run First-Run Wizard style detection. Returns {tool: path_or_None}."""
    results = {}
    for tool in REQUIRED_TOOLS:
        path = cfg.get_tool(tool)
        results[tool] = path
    cfg.save()
    return results


if __name__ == "__main__":
    c = Config.load()
    res = detect_all_tools(c)
    for tool, path in res.items():
        status = f"FOUND -> {path}" if path else "MISSING"
        print(f"[{'✓' if path else '✗'}] {tool}: {status}")
