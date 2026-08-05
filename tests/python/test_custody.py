"""Tests for tamper-evident custody ledger."""

from __future__ import annotations

from pathlib import Path

import pytest

from endpoint_incident_triage.custody import (
    GENESIS_HASH,
    CustodyError,
    append_record,
    compute_record_hash,
    make_record,
    read_ledger,
    verify_ledger,
    write_ledger,
)
from tests.helpers.factories import make_custody_ledger


def test_make_record_hash_chain():
    record = make_record(
        sequence=1,
        event_type="case_created",
        package_id="pkg-1",
        actor_label="OP",
        action="create",
        details={"case_id": "TEST"},
    )
    assert len(record.record_hash) == 64
    assert record.previous_record_hash == GENESIS_HASH


def test_append_record_links_previous_hash():
    ledger = make_custody_ledger()
    first_hash = ledger[-1].record_hash
    append_record(
        ledger,
        event_type="collection_completed",
        package_id=ledger[0].package_id,
        actor_label="OP",
        action="complete",
        details={},
    )
    assert ledger[-1].previous_record_hash == first_hash


def test_verify_ledger_ok():
    ledger = make_custody_ledger()
    result = verify_ledger(ledger)
    assert result.ok
    assert result.record_count == 2


def test_verify_ledger_detects_mutation():
    ledger = make_custody_ledger()
    ledger[0].details = {"tampered": True}
    result = verify_ledger(ledger)
    assert not result.ok
    assert any("hash mismatch" in err.lower() for err in result.errors)


def test_verify_ledger_detects_reorder():
    ledger = make_custody_ledger()
    append_record(
        ledger,
        event_type="collection_completed",
        package_id=ledger[0].package_id,
        actor_label="OP",
        action="complete",
        details={},
    )
    ledger[0], ledger[1] = ledger[1], ledger[0]
    result = verify_ledger(ledger)
    assert not result.ok


def test_verify_ledger_detects_deletion_gap():
    ledger = make_custody_ledger()
    append_record(
        ledger,
        event_type="collection_completed",
        package_id=ledger[0].package_id,
        actor_label="OP",
        action="complete",
        details={},
    )
    del ledger[1]
    ledger[1].sequence = 2
    result = verify_ledger(ledger)
    assert not result.ok


def test_write_and_read_ledger_roundtrip(tmp_path: Path):
    ledger = make_custody_ledger()
    path = tmp_path / "custody.jsonl"
    write_ledger(path, ledger)
    loaded = read_ledger(path)
    assert len(loaded) == len(ledger)
    assert verify_ledger(loaded).ok


def test_make_record_sanitizes_secrets_in_details():
    record = make_record(
        sequence=1,
        event_type="case_created",
        package_id="pkg",
        actor_label="OP",
        action="create",
        details={"note": "password=SuperSecret123"},
    )
    assert "[REDACTED]" in record.details["note"]


def test_unsupported_event_type_raises():
    with pytest.raises(CustodyError, match="Unsupported custody event"):
        make_record(
            sequence=1,
            event_type="evil_event",
            package_id="pkg",
            actor_label="OP",
            action="hack",
        )


def test_compute_record_hash_excludes_record_hash_field():
    record = make_record(
        sequence=1,
        event_type="case_created",
        package_id="pkg",
        actor_label="OP",
        action="create",
    )
    data = record.to_dict()
    data["record_hash"] = "deadbeef"
    assert compute_record_hash(data) == record.record_hash
