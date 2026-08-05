# Timeline model

## Purpose

The timeline aggregates timestamped observations from collector records into a single UTC-sorted JSONL file for analyst review.

## Event fields

| Field | Description |
|-------|-------------|
| `timestamp_utc` | Normalized UTC ISO 8601 |
| `timestamp_source` | Origin field or inference rule |
| `timestamp_precision` | `second`, `minute`, `day`, `unknown` |
| `platform` | `windows` or `linux` |
| `collector_id` | Source collector |
| `event_type` | Semantic category |
| `entity_type` | e.g. process, service, logon |
| `entity_id` | Stable identifier within artifact |
| `summary` | Human-readable short text |
| `details` | Additional structured context |
| `confidence` | `high`, `medium`, `low` |
| `source_artifact` | Relative artifact path |
| `original_timestamp` | Unmodified source value |
| `timezone_assumption` | Documented assumption when inferred |

## Sorting

Events sort deterministically by `timestamp_utc`, then collector, then entity.

## Clock and timezone limitations

- System clock may be wrong or skewed
- Some sources lack timezone information
- Low-precision timestamps (date-only) reduce correlation confidence
- Collection time ≠ event time for historical log entries

Warnings may appear in case `limitations` when inferred timestamps are used.

## Original values preserved

Normalization does not discard original timestamp strings; they remain in `original_timestamp` for audit.

See [methodology.md](methodology.md).
