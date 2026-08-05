"""Tests for triage rules loading and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from endpoint_incident_triage.config import load_config
from endpoint_incident_triage.rules import RulesError, load_rules, validate_rules_dict
from tests.helpers.factories import demo_config_path


def test_load_rules_from_demo_config():
    config = load_config(demo_config_path())
    rules = load_rules(config.rules_path)
    assert len(rules) > 0
    assert all(rule.advisory_wording for rule in rules)


def test_rules_advisory_wording_allowlist():
    config = load_config(demo_config_path())
    rules = load_rules(config.rules_path)
    allowed = {
        "Requires review",
        "Potentially suspicious",
        "Heuristic match",
        "Context-dependent",
    }
    for rule in rules:
        assert rule.advisory_wording in allowed


def test_rules_reject_forbidden_eval_key(tmp_path: Path):
    payload = {
        "rules": [
            {
                "id": "bad",
                "title": "Bad",
                "platform": "any",
                "artifact_type": "any",
                "enabled": True,
                "priority": 1,
                "severity": "Low",
                "conditions": [{"type": "equals", "field": "x", "value": 1}],
                "advisory_wording": "Requires review",
                "eval": "dangerous()",
            }
        ]
    }
    errors = validate_rules_dict(payload)
    assert errors and "Forbidden rule key" in errors[0]
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RulesError):
        load_rules(path)


def test_rules_reject_invalid_condition_type(tmp_path: Path):
    payload = {
        "rules": [
            {
                "id": "bad",
                "title": "Bad",
                "platform": "any",
                "artifact_type": "any",
                "enabled": True,
                "priority": 1,
                "severity": "Low",
                "conditions": [{"type": "exec", "field": "x"}],
                "advisory_wording": "Requires review",
            }
        ]
    }
    errors = validate_rules_dict(payload)
    assert errors


def test_rules_reject_duplicate_ids(tmp_path: Path, demo_config_path=demo_config_path):
    config = load_config(demo_config_path())
    payload = json.loads(config.rules_path.read_text(encoding="utf-8"))
    payload["rules"].append(payload["rules"][0])
    path = tmp_path / "dup.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RulesError, match="Duplicate"):
        load_rules(path)


def test_rules_regex_condition_compiled():
    config = load_config(demo_config_path())
    rules = load_rules(config.rules_path)
    regex_rules = [r for r in rules if any(c.type == "regex" for c in r.conditions)]
    assert regex_rules
    for rule in regex_rules:
        for cond in rule.conditions:
            if cond.type == "regex":
                assert cond._compiled_regex is not None
