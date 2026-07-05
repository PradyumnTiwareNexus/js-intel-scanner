from backend.core.config import Config


def test_effective_pipeline_default_enables_everything():
    cfg = Config()
    cfg.active_profile = "balanced"
    assert cfg.effective_pipeline() == cfg.pipeline


def test_fast_profile_disables_expected_stages():
    cfg = Config()
    cfg.active_profile = "fast"
    effective = set(cfg.effective_pipeline())
    for stage in cfg.profiles["fast"]["disable"]:
        assert stage not in effective


def test_disabling_a_stage_directly_removes_it_from_effective_pipeline():
    cfg = Config()
    cfg.stages["nuclei"]["enabled"] = False
    assert "nuclei" not in cfg.effective_pipeline()
    assert "nuclei" in cfg.pipeline  # order/definition unchanged, just skipped


def test_stage_cfg_merges_profile_worker_override():
    cfg = Config()
    cfg.active_profile = "deep"
    assert cfg.stage_cfg("katana")["workers"] == cfg.profiles["deep"]["workers"]["katana"]


def test_reordering_pipeline_is_respected():
    cfg = Config()
    cfg.pipeline = list(reversed(cfg.pipeline))
    assert cfg.effective_pipeline()[0] == cfg.pipeline[0]
