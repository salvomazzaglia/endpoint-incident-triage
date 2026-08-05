# Collection order

## Volatility rationale

Live endpoints lose ephemeral evidence continuously. Collectors run in ascending `volatility_order` from the registry:

| Order | Category | Rationale |
|------:|----------|-----------|
| 1–2 | System/time context | Establish clock and environment baseline |
| 3 | Users/sessions | Session state changes quickly |
| 4 | Processes | Process list is highly volatile |
| 5 | Network connections | Connections open and close rapidly |
| 6–7 | Services, scheduled tasks/timers | Persistence context |
| 8–9 | Autoruns, WMI/cron, SSH metadata | Additional persistence |
| 10 | Defender / security tool status | Posture snapshot |
| 11 | Event summaries | Bounded historical view |
| 12 | Recent-file metadata | Lowest priority; higher disk interaction |

## Practical limitations

- Order reduces risk but **does not guarantee** volatile evidence survives
- Some collectors depend on OS APIs that reorder internally
- Clock skew affects event correlation
- Optional collectors may be `Unavailable` without failing the case (unless `--strict`)

## Side effects

Even read-oriented commands may:

- Touch file access timestamps in searched directories
- Trigger EDR telemetry
- Consume CPU/memory during enumeration

Document limitations in case metadata automatically.

## Configuration

Ordering is defined per collector in `config/collector-registry.json` (`volatility_order` field). Profiles select subsets; the runner sorts selected collectors by this field.

See [collection-profiles.md](collection-profiles.md).
