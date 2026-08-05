"""Process exit codes for endpoint-incident-triage."""

from __future__ import annotations

EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_FAILURE = 2
EXIT_ERROR = 3

EXIT_CODE_MEANINGS: dict[int, str] = {
    EXIT_OK: (
        "Requested operation completed successfully. All mandatory collectors "
        "collected or were intentionally skipped; package verification passed."
    ),
    EXIT_PARTIAL: (
        "Partial success: optional collectors unavailable, non-fatal truncation "
        "or warnings; package may still be verifiable."
    ),
    EXIT_FAILURE: (
        "Mandatory collector failure, manifest/custody/package integrity failure, "
        "or (with --fail-on-high-finding) High/Critical heuristic findings."
    ),
    EXIT_ERROR: (
        "Invalid configuration, invalid case metadata, output-path failure, "
        "or unexpected internal error."
    ),
}
