"""Heuristic finding evaluation against collector results."""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any

from endpoint_incident_triage.models import CollectorResult, Finding
from endpoint_incident_triage.rules import RuleCondition, TriageRule
from endpoint_incident_triage.statuses import FindingSeverity


def _field_value(record: dict[str, Any], field: str) -> Any:
    """Resolve dotted field paths."""
    current: Any = record
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _as_string(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _path_norm(value: str) -> str:
    return value.replace("\\", "/").lower()


def evaluate_condition(condition: RuleCondition, record: dict[str, Any]) -> bool:
    """Evaluate a single safe rule condition against a record."""
    if condition.type == "field_missing":
        return _field_value(record, condition.field_name or "") is None

    value = _field_value(record, condition.field_name or "")
    text = _as_string(value)

    if condition.type == "equals":
        return text == _as_string(condition.value)
    if condition.type == "not_equals":
        return text != _as_string(condition.value)
    if condition.type == "contains":
        return _as_string(condition.value) in text
    if condition.type == "regex":
        if condition._compiled_regex is None:
            return False
        return condition._compiled_regex.search(text) is not None
    if condition.type == "path_under":
        prefix = _path_norm(_as_string(condition.prefix or condition.value))
        return _path_norm(text).startswith(prefix)
    if condition.type == "path_missing":
        path_text = _path_norm(text)
        return not path_text or path_text in {"n/a", "unknown", "-"}
    if condition.type == "numeric_greater_than":
        try:
            numeric = float(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        return numeric > float(condition.minimum or 0)
    if condition.type == "value_in":
        return text in {_as_string(item) for item in condition.values}
    if condition.type == "network_scope":
        try:
            addr = ipaddress.ip_address(text.split("%")[0])
            network = ipaddress.ip_network(condition.scope or "0.0.0.0/0", strict=False)
            return addr in network
        except ValueError:
            return False
    return False


def record_matches_rule(rule: TriageRule, record: dict[str, Any]) -> bool:
    """Return True when all conditions match (AND semantics)."""
    return all(evaluate_condition(condition, record) for condition in rule.conditions)


def evaluate_findings(
    collector_results: list[CollectorResult],
    rules: list[TriageRule],
) -> list[Finding]:
    """Evaluate triage rules against collector results."""
    findings: list[Finding] = []
    enabled_rules = [rule for rule in rules if rule.enabled]
    enabled_rules.sort(key=lambda item: (item.priority, item.id))

    for collector in collector_results:
        for rule in enabled_rules:
            if rule.platform not in {"any", collector.platform}:
                continue
            if rule.artifact_type not in {
                "any",
                collector.category,
                collector.collector_id,
            }:
                # Also allow matching record-level artifact_type when rule uses domain labels.
                record_types = {
                    str(item.get("artifact_type", "")).lower()
                    for item in collector.records
                    if isinstance(item, dict)
                }
                if rule.artifact_type.lower() not in record_types:
                    continue
            for index, record in enumerate(collector.records):
                record_artifact = str(record.get("artifact_type", "")).lower()
                if (
                    rule.artifact_type
                    not in {
                        "any",
                        collector.category,
                        collector.collector_id,
                    }
                    and rule.artifact_type.lower() != record_artifact
                ):
                    continue
                if not record_matches_rule(rule, record):
                    continue
                entity_id = _as_string(
                    record.get("entity_id")
                    or record.get("id")
                    or record.get("pid")
                    or record.get("name")
                    or index
                )
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        rule_id=rule.id,
                        title=rule.title,
                        description=rule.description,
                        severity=rule.severity,
                        platform=collector.platform,
                        artifact_type=collector.category,
                        entity_id=entity_id,
                        rationale=rule.rationale,
                        recommendation=rule.recommendation,
                        references=list(rule.references),
                        tags=list(rule.tags),
                        advisory_wording=rule.advisory_wording,
                        source_artifact=(
                            f"artifacts/{collector.platform}/{collector.collector_id}.json"
                        ),
                    )
                )
    findings.sort(key=lambda item: (severity_rank(item.severity), item.rule_id, item.entity_id))
    return findings


def severity_rank(severity: FindingSeverity) -> int:
    order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFORMATIONAL: 4,
    }
    return order.get(severity, 99)


def highest_severity(findings: list[Finding]) -> FindingSeverity | None:
    """Return the highest finding severity."""
    if not findings:
        return None
    return min(findings, key=lambda item: severity_rank(item.severity)).severity


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    """Count findings grouped by severity label."""
    counts = {severity.value: 0 for severity in FindingSeverity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def is_writable_temp_path(path: str) -> bool:
    """Helper for path-based heuristics."""
    normalized = _path_norm(path)
    temp_markers = ("/tmp/", "/temp/", "\\temp\\", "/appdata/local/temp/")
    return any(marker in normalized for marker in temp_markers)


def is_missing_path_reference(path: str) -> bool:
    """Return True when a referenced path appears absent."""
    text = _path_norm(path)
    return not text or text in {"missing", "not found", "n/a", "unknown"}
