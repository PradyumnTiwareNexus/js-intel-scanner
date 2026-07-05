# Contributing

## Adding a new secret detector

Add a `(regex, severity)` tuple to `PATTERNS` in
`backend/detectors/patterns.py`. Keep the redaction helper in place — never
land a change that stores full plaintext secrets in reports.

## Adding a new recon/crawl source

Scanners are plugin-style async functions returning a `set[str]`. Add yours
to `backend/scanners/recon.py` or `crawl.py`, then wire it into the
`asyncio.gather(...)` call in `enumerate_subdomains` / `collect_all_urls`.

## Adding a new external tool wrapper

Follow the pattern in `backend/detectors/external_tools.py`: resolve the
binary via `cfg.get_tool("name")`, run it through `core/runner.run_tool`,
parse its JSON/JSONL output into the common finding schema:

```python
{"type": ..., "match": ..., "severity": ..., "source": ..., "detector": ...}
```

## Tests

```bash
pip install pytest pytest-asyncio ruff
ruff check backend
pytest tests/ -v
```

## Style

- Type hints on all function signatures.
- No hard-coded binary paths — always go through `Config.get_tool()`.
- Never write unredacted secrets to disk.
