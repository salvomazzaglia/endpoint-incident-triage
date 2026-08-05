# Reports

## Generation

Reports require a **verified** evidence package:

```bash
endpoint-incident-triage report \
  --package examples/synthetic-evidence-package \
  --output-directory temp/reports \
  --format all \
  --privacy-mode masked \
  --config config/demo.config.json
```

## Formats

| Format | Output |
|--------|--------|
| `json` | `triage-report.json` |
| `html` | `triage-report.html` |
| `all` | Both files |

Public samples are copied to `examples/sample-triage-report.json` and `examples/sample-triage-report.html` by `scripts/generate-sample-reports.py`.

## Report contents

- Case and collection summary
- Collector status counts
- Integrity and custody status
- Finding counts and highest severity
- Findings list with recommendations
- Timeline preview
- Limitations and security notice
- Privacy mode indicator
- Synthetic banner when applicable

## HTML properties

- Fully standalone (no CDN, external CSS, JS, fonts, or images)
- HTML-escaped dynamic fields
- Accessible contrast and responsive layout
- Opens offline

## Options

| Option | Description |
|--------|-------------|
| `--privacy-mode` | `masked`, `hashed`, `full` |
| `--hash-salt-env` | Environment variable for salt (default `EIT_HASH_SALT`) |
| `--include-low-severity` | Include Informational/Low findings |
| `--fail-on-high-finding` | Exit 2 on High/Critical findings |

## Screenshot

`docs/images/sample-triage-report.png` captured from synthetic HTML via `scripts/capture-sample-report-screenshot.py`.

See [privacy-and-redaction.md](privacy-and-redaction.md).
