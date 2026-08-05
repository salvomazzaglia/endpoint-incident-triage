"""Safe triage-rules.json loading and validation."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from endpoint_incident_triage.statuses import FindingSeverity

ALLOWED_CONDITION_TYPES = frozenset(
    {
        "equals",
        "not_equals",
        "contains",
        "regex",
        "path_under",
        "path_missing",
        "field_missing",
        "numeric_greater_than",
        "value_in",
        "network_scope",
    }
)

FORBIDDEN_RULE_KEYS = frozenset({"expression", "eval", "exec", "script", "python", "lambda"})


class RulesError(ValueError):
    """Triage rules validation error."""


@dataclass(slots=True)
class RuleCondition:
    type: str
    field_name: str | None = None
    value: Any = None
    pattern: str | None = None
    prefix: str | None = None
    scope: str | None = None
    minimum: float | None = None
    values: list[Any] = field(default_factory=list)
    _compiled_regex: re.Pattern[str] | None = field(default=None, repr=False)

    def compiled_regex(self) -> re.Pattern[str]:
        if self._compiled_regex is None:
            raise RulesError("Regex not compiled")
        return self._compiled_regex


@dataclass(slots=True)
class TriageRule:
    id: str
    title: str
    description: str
    platform: str
    artifact_type: str
    enabled: bool
    priority: int
    conditions: list[RuleCondition]
    severity: FindingSeverity
    rationale: str
    recommendation: str
    references: list[str]
    tags: list[str]
    advisory_wording: str


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RulesError(f"{label} must be an object")
    return value


def _parse_condition(raw: dict[str, Any]) -> RuleCondition:
    for forbidden in FORBIDDEN_RULE_KEYS:
        if forbidden in raw:
            raise RulesError(f"Forbidden condition key: {forbidden}")
    cond_type = raw.get("type")
    if cond_type not in ALLOWED_CONDITION_TYPES:
        raise RulesError(f"Unsupported condition type: {cond_type}")
    condition = RuleCondition(
        type=str(cond_type),
        field_name=str(raw["field"]) if raw.get("field") is not None else None,
        value=raw.get("value"),
        pattern=str(raw["pattern"]) if raw.get("pattern") is not None else None,
        prefix=str(raw["prefix"]) if raw.get("prefix") is not None else None,
        scope=str(raw["scope"]) if raw.get("scope") is not None else None,
        minimum=float(raw["minimum"]) if raw.get("minimum") is not None else None,
        values=list(raw.get("values") or []),
    )
    if condition.type == "regex":
        if not condition.pattern:
            raise RulesError("regex condition requires pattern")
        try:
            condition._compiled_regex = re.compile(condition.pattern)
        except re.error as exc:
            raise RulesError(f"Invalid regex pattern: {exc}") from exc
    if condition.type in {"equals", "not_equals", "contains", "path_under", "path_missing"}:
        if not condition.field_name:
            raise RulesError(f"{condition.type} condition requires field")
    if condition.type == "field_missing" and condition.field_name is None:
        raise RulesError("field_missing condition requires field")
    if condition.type == "numeric_greater_than":
        if condition.field_name is None or condition.minimum is None:
            raise RulesError("numeric_greater_than requires field and minimum")
    if condition.type == "value_in":
        if condition.field_name is None or not condition.values:
            raise RulesError("value_in requires field and values")
    if condition.type == "network_scope":
        if condition.field_name is None or not condition.scope:
            raise RulesError("network_scope requires field and scope")
        try:
            ipaddress.ip_network(condition.scope, strict=False)
        except ValueError as exc:
            raise RulesError(f"Invalid network scope: {exc}") from exc
    return condition


def _parse_rule(raw: dict[str, Any]) -> TriageRule:
    for forbidden in FORBIDDEN_RULE_KEYS:
        if forbidden in raw:
            raise RulesError(f"Forbidden rule key: {forbidden}")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise RulesError("Rule id must be a non-empty string")
    platform = raw.get("platform", "any")
    if platform not in {"windows", "linux", "any"}:
        raise RulesError(f"Invalid platform for rule {rule_id}")
    severity_raw = str(raw.get("severity", "Informational")).strip()
    severity_map = {item.value.lower(): item for item in FindingSeverity}
    severity = severity_map.get(severity_raw.lower())
    if severity is None:
        raise RulesError(f"Invalid severity for rule {rule_id}: {severity_raw}")
    conditions_raw = raw.get("conditions")
    if not isinstance(conditions_raw, list) or not conditions_raw:
        raise RulesError(f"Rule {rule_id} must have at least one condition")
    conditions = [_parse_condition(_require_dict(item, "condition")) for item in conditions_raw]
    advisory = str(raw.get("advisory_wording", "Requires review"))
    allowed_wording = {
        "Requires review",
        "Potentially suspicious",
        "Heuristic match",
        "Context-dependent",
    }
    if advisory not in allowed_wording:
        raise RulesError(f"Invalid advisory_wording for rule {rule_id}: {advisory}")
    return TriageRule(
        id=rule_id,
        title=str(raw.get("title", rule_id)),
        description=str(raw.get("description", "")),
        platform=platform,
        artifact_type=str(raw.get("artifact_type", "any")),
        enabled=bool(raw.get("enabled", True)),
        priority=int(raw.get("priority", 100)),
        conditions=conditions,
        severity=severity,
        rationale=str(raw.get("rationale", "")),
        recommendation=str(raw.get("recommendation", "")),
        references=[str(item) for item in raw.get("references") or []],
        tags=[str(item) for item in raw.get("tags") or []],
        advisory_wording=advisory,
    )


def load_rules(path: Path) -> list[TriageRule]:
    """Load and validate triage rules from JSON."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RulesError(f"Unable to load rules: {exc}") from exc
    data = _require_dict(payload, str(path))
    rules_raw = data.get("rules")
    if not isinstance(rules_raw, list):
        raise RulesError("rules must be an array")
    rules = [_parse_rule(_require_dict(item, "rule")) for item in rules_raw]
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise RulesError(f"Duplicate rule id: {rule.id}")
        seen.add(rule.id)
    return sorted(rules, key=lambda item: (item.priority, item.id))


def validate_rules_dict(payload: dict[str, Any]) -> list[str]:
    """Validate rules payload; return error messages (empty if valid)."""
    try:
        rules_raw = payload.get("rules")
        if not isinstance(rules_raw, list):
            return ["rules must be an array"]
        for item in rules_raw:
            if not isinstance(item, dict):
                return ["each rule must be an object"]
            _parse_rule(item)
        return []
    except RulesError as exc:
        return [str(exc)]
