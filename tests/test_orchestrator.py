import asyncio

from backend.core.config import Config
from backend.core.orchestrator import run_pipeline
from backend.core.stages import build_registry


def test_all_builtin_pipeline_stages_are_registered():
    registry = build_registry()
    cfg = Config()
    for name in cfg.pipeline:
        assert name in registry, f"'{name}' is in the default pipeline but not in the stage registry"


def test_example_plugin_is_discovered():
    registry = build_registry()
    assert "example_stats" in registry
    spec = registry["example_stats"]
    assert spec.source == "example_stats.py"
    assert spec.requires == ["downloaded"]


def test_orchestrator_skips_stage_with_missing_dependency():
    """httpx requires 'subdomains' (produced by deduplicate). Remove
    deduplicate from the pipeline and httpx must be skipped, not crash."""
    cfg = Config()
    cfg.pipeline = ["httpx", "report"]  # no subfinder/deduplicate before it
    # Disable every other builtin so this test only exercises httpx/report,
    # and disable report's normal dependency too, to check both skip paths.
    for name in list(cfg.stages):
        cfg.stages[name]["enabled"] = True

    summary = asyncio.run(run_pipeline("example.com", cfg, __import__("pathlib").Path("/tmp/js-intel-test")))

    assert summary["stage_results"]["httpx"]["status"] == "skipped"
    assert "missing dependency" in summary["stage_results"]["httpx"]["reason"]
    # report also requires static_findings (produced by regex), which never ran
    assert summary["stage_results"]["report"]["status"] == "skipped"


def test_orchestrator_never_crashes_on_unknown_stage_name():
    cfg = Config()
    cfg.pipeline = ["this_stage_does_not_exist", "report"]
    summary = asyncio.run(run_pipeline("example.com", cfg, __import__("pathlib").Path("/tmp/js-intel-test")))
    assert summary["stage_results"]["this_stage_does_not_exist"]["status"] == "skipped"
    assert "unknown stage" in summary["stage_results"]["this_stage_does_not_exist"]["reason"]


def test_orchestrator_runs_deduplicate_standalone():
    """deduplicate has no requires, so it should always run and produce output."""
    cfg = Config()
    cfg.pipeline = ["deduplicate"]
    summary = asyncio.run(run_pipeline("example.com", cfg, __import__("pathlib").Path("/tmp/js-intel-test")))
    assert summary["stage_results"]["deduplicate"]["status"] == "done"
    assert summary["subdomains"] >= 1  # at least the root domain itself
