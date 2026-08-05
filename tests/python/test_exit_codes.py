"""Tests for process exit codes."""

from __future__ import annotations

from endpoint_incident_triage.exit_codes import (
    EXIT_CODE_MEANINGS,
    EXIT_ERROR,
    EXIT_FAILURE,
    EXIT_OK,
    EXIT_PARTIAL,
)


def test_exit_codes_are_distinct():
    codes = {EXIT_OK, EXIT_PARTIAL, EXIT_FAILURE, EXIT_ERROR}
    assert len(codes) == 4


def test_exit_code_meanings_cover_all_codes():
    assert set(EXIT_CODE_MEANINGS) == {EXIT_OK, EXIT_PARTIAL, EXIT_FAILURE, EXIT_ERROR}


def test_exit_ok_description():
    assert "successfully" in EXIT_CODE_MEANINGS[EXIT_OK].lower()


def test_exit_error_description():
    assert "configuration" in EXIT_CODE_MEANINGS[EXIT_ERROR].lower()


def test_exit_failure_description():
    assert (
        "integrity" in EXIT_CODE_MEANINGS[EXIT_FAILURE].lower()
        or "mandatory" in EXIT_CODE_MEANINGS[EXIT_FAILURE].lower()
    )
