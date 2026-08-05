"""Tests for heuristic finding evaluation."""

from __future__ import annotations

from endpoint_incident_triage.config import load_config
from endpoint_incident_triage.findings import (
    count_by_severity,
    evaluate_condition,
    evaluate_findings,
    highest_severity,
    is_missing_path_reference,
    is_writable_temp_path,
    record_matches_rule,
    severity_rank,
)
from endpoint_incident_triage.rules import RuleCondition, load_rules
from endpoint_incident_triage.statuses import FindingSeverity
from tests.helpers.factories import demo_config_path, make_collector_result, make_rule


def test_evaluate_condition_equals():
    cond = RuleCondition(type="equals", field_name="status", value="running")
    assert evaluate_condition(cond, {"status": "running"})


def test_evaluate_condition_contains():
    cond = RuleCondition(type="contains", field_name="path", value="Temp")
    assert evaluate_condition(cond, {"path": r"C:\Users\x\AppData\Local\Temp\a.exe"})


def test_evaluate_condition_regex():
    cond = RuleCondition(type="regex", field_name="path", pattern="(?i)temp")
    cond._compiled_regex = __import__("re").compile("(?i)temp")
    assert evaluate_condition(cond, {"path": r"C:\Temp\evil.exe"})


def test_evaluate_condition_network_scope():
    cond = RuleCondition(type="network_scope", field_name="remote_ip", scope="10.0.0.0/8")
    assert evaluate_condition(cond, {"remote_ip": "10.1.2.3"})


def test_record_matches_rule_all_conditions():
    rule = make_rule(
        conditions=[
            RuleCondition(type="equals", field_name="artifact_type", value="process"),
            RuleCondition(type="contains", field_name="path", value="Temp"),
        ]
    )
    record = {
        "artifact_type": "process",
        "path": r"C:\Temp\payload.exe",
        "pid": 99,
    }
    assert record_matches_rule(rule, record)


def test_evaluate_findings_from_synthetic_processes():
    config = load_config(demo_config_path())
    rules = load_rules(config.rules_path)
    result = make_collector_result(platform="windows", collector_id="windows.processes")
    findings = evaluate_findings([result], rules)
    assert findings
    assert all(f.advisory_wording for f in findings)
    assert all(
        f.advisory_wording
        in {
            "Requires review",
            "Potentially suspicious",
            "Heuristic match",
            "Context-dependent",
        }
        for f in findings
    )


def test_highest_severity():
    from tests.helpers.factories import make_finding

    findings = [
        make_finding(severity=FindingSeverity.LOW),
        make_finding(severity=FindingSeverity.HIGH),
    ]
    assert highest_severity(findings) == FindingSeverity.HIGH


def test_count_by_severity():
    from tests.helpers.factories import make_finding

    findings = [make_finding(severity=FindingSeverity.MEDIUM)]
    counts = count_by_severity(findings)
    assert counts["Medium"] == 1


def test_severity_rank_order():
    assert severity_rank(FindingSeverity.CRITICAL) < severity_rank(FindingSeverity.LOW)


def test_is_writable_temp_path():
    assert is_writable_temp_path(r"C:\Users\x\AppData\Local\Temp\a.exe")


def test_is_missing_path_reference():
    assert is_missing_path_reference("missing")
