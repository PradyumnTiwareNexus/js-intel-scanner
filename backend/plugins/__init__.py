"""
Drop-in scanner plugins.

Any .py file placed directly in this folder (not starting with "_") is
auto-discovered by backend/core/stages.py at pipeline build time. A plugin
must define:

    STAGE_NAME = "my_stage"          # unique name, used in configs/config.yaml pipeline list
    REQUIRES   = ["downloaded"]      # ctx keys that must already be populated
    PRODUCES   = ["my_findings"]     # ctx keys this stage sets on success

    async def run(ctx, cfg, on_line=None) -> dict:
        ...
        return {"items_found": N}

See example_stats.py for a minimal, fully working reference implementation.
No restart or code change elsewhere is required — add the file, then add
its STAGE_NAME to the `pipeline:` list in configs/config.yaml (or via the
web UI's Pipeline tab) to wire it in.
"""
