from backend.core.config import Config, DEFAULTS


def test_config_defaults():
    cfg = Config()
    assert cfg.threads == DEFAULTS["threads"]
    assert cfg.tool_paths == {}


def test_get_tool_returns_none_for_missing_binary():
    cfg = Config()
    assert cfg.get_tool("definitely_not_a_real_binary_xyz") is None


def test_httpx_rejects_python_httpx_cli(tmp_path):
    """A fake `httpx` binary that behaves like the Click-based Python httpx
    CLI (errors on -version with a Usage: line) must be rejected, not
    silently trusted — this is the exact name-collision bug that breaks
    the recon pipeline when pip's httpx shadows ProjectDiscovery's httpx."""
    fake = tmp_path / "httpx"
    fake.write_text("#!/bin/sh\necho 'Usage: httpx [OPTIONS] URL' >&2\nexit 2\n")
    fake.chmod(0o755)
    cfg = Config()
    cfg.tool_paths["httpx"] = str(fake)
    assert cfg.get_tool("httpx") is None


def test_httpx_accepts_projectdiscovery_style_binary(tmp_path):
    """A fake binary that behaves like ProjectDiscovery's httpx (exits 0 on
    -version with a banner) must be accepted."""
    fake = tmp_path / "httpx"
    fake.write_text("#!/bin/sh\necho 'Current Version: v1.6.0'\nexit 0\n")
    fake.chmod(0o755)
    cfg = Config()
    cfg.tool_paths["httpx"] = str(fake)
    assert cfg.get_tool("httpx") == str(fake)
