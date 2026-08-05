# Collection profiles

## Profiles

### minimal

Fast, low-impact triage for initial scoping:

- System and OS context
- UTC/local time context
- Logged-on users and sessions
- Process metadata (no command lines by default)
- Network connection metadata
- Windows services / Linux systemd services
- Scheduled tasks / systemd timers
- Basic persistence (autoruns; not WMI/cron in minimal on all platforms)
- Bounded security-event summary
- Windows Defender status where available

Recommended for: remote constrained environments, high-volatility endpoints, first-pass triage.

### standard

Extended triage when persistence review is needed:

- All minimal collectors
- WMI persistence metadata (Windows)
- Cron persistence metadata (Linux)
- SSH authorized_keys **metadata** (no key content)
- Extended bounded event summaries
- Optional recent-file metadata in allowlisted locations

Recommended for: suspected persistence, lateral movement review, post-compromise scoping.

## Selection

```bash
endpoint-incident-triage plan --config config/default.config.json --profile minimal --platform windows
endpoint-incident-triage collect-synthetic --case-id DEMO --platform linux --profile standard --output-directory temp/out
```

## Optional collectors

Some collectors are optional (`mandatory: false` in registry). They may return `Unavailable` on unsupported hosts without failing the package (exit code 1 unless `--strict`).

## Configuration file

Profile definitions: `config/collection-profiles.json`

Collector membership: `config/collector-registry.json` (`profile` field per collector)

## No "collect everything" profile

Output size limits, timeouts, and allowlisted roots prevent unbounded collection. Arbitrary user-supplied collector paths are rejected.
