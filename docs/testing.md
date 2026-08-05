# Testing

## Philosophy

- **No live host inspection in CI or unit tests**
- Synthetic fixtures under `tests/fixtures/` and `examples/synthetic-input/`
- Meaningful assertions over trivial duplication
- Cross-platform coverage: pytest (all), Pester (Windows), Bats (Linux)

## pytest

Location: `tests/python/`

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/python -v
python -m pytest tests/python/test_repository_guards.py
```

Covers: config, registry, runner, manifest, custody, verification, privacy, reports, CLI, repository guards.

## Pester

Location: `tests/pester/`

```powershell
Install-Module Pester -Scope CurrentUser
Invoke-Pester -Path tests/pester
```

Covers: StrictMode, fixture mode, static safety patterns, JSON output protocol.

## Bats

Location: `tests/bats/`

```bash
bats tests/bats/
```

Requires Bash 5+ and Python 3 for JSON validation helpers.

## Static analysis

| Tool | Target |
|------|--------|
| Ruff | Python lint + format |
| mypy | Python types |
| PSScriptAnalyzer | PowerShell collectors |
| ShellCheck | Bash collectors |
| shfmt | Bash formatting |

## Local CI script

```bash
python scripts/run-ci.py
```

Runs available checks; skips tools not installed locally with clear messages.

## Synthetic integration

```bash
python scripts/generate-demo-data.py
python scripts/generate-sample-package.py
python scripts/generate-sample-reports.py
```

## CI

GitHub Actions matrix: Ubuntu and Windows × Python 3.11 and 3.12. See `.github/workflows/ci.yml`.

## Adding tests

- New collectors: add fixture JSON + Pester/Bats coverage
- New rules: pytest in `test_findings.py` / `test_rules.py`
- Never commit live endpoint output

See [CONTRIBUTING.md](../CONTRIBUTING.md).
