# Troubleshooting

## Configuration errors (exit 3)

**Symptom:** `Validation failed` or `ConfigError`

- Run `endpoint-incident-triage validate-config --config your.config.json`
- Ensure paths are relative and stay within repository layout
- Check for duplicate collector IDs in registry

## Output path refused

**Symptom:** `Unsafe output directory` or `inside source tree`

- Do not write to `C:\Windows`, `/etc`, or inside `collectors/`
- Choose a dedicated evidence directory outside the repo

## Collector unavailable (exit 1)

**Symptom:** Status `Unavailable` for optional collectors

- Expected on CI Linux for Windows-only collectors (use platform-specific synthetic collection)
- Defender/WMI may require elevation or OS SKU on Windows
- Use `--verbose` and inspect `logs/collector-execution.jsonl`

## Verification failures (exit 2)

**Symptom:** Manifest or custody mismatch

- Do not manually edit files after manifest finalization
- Re-run collection if package is corrupted
- For ZIP: ensure complete transfer; re-verify checksum

## Report refused

**Symptom:** `Package verification failed; refusing to generate report`

- Fix integrity issues first with `verify --verbose`
- Extract ZIP to a clean directory if path confusion occurs

## Privacy / salt warnings

**Symptom:** Hashed mode warns about missing salt

- Export `EIT_HASH_SALT` before `report`
- Use masked mode for demos

## Pester / Bats failures locally

- Ensure fixture files exist: `python scripts/generate-demo-data.py`
- Windows: run Pester in PowerShell 5.1+
- Linux: install `bats`, `shellcheck`, `shfmt`

## Python import errors

```bash
python -m pip install -e ".[dev]"
export PYTHONPATH=src   # if not using editable install
```

## Still stuck?

Open a bug report with synthetic reproduction steps only — no real host data.
