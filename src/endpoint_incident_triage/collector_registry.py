"""Allowlisted collector registry."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from endpoint_incident_triage.config import (
    MAX_OUTPUT_BYTES,
    MAX_TIMEOUT_SECONDS,
    ConfigError,
    _looks_absolute_path,
)

ALLOWED_INTERPRETERS = frozenset({"powershell", "bash"})
ALLOWED_PRIVILEGES = frozenset({"standard", "elevated_optional", "elevated_preferred"})


@dataclass(slots=True)
class CollectorDefinition:
    id: str
    platform: str
    script_path: str
    category: str
    profile: str
    mandatory: bool
    volatility_order: int
    privilege: str
    timeout_seconds: int
    maximum_output_bytes: int
    required_commands: list[str]
    description: str
    sensitive_fields: list[str]
    interpreter: str
    optional_in_profiles: list[str] = field(default_factory=list)

    @property
    def resolved_script(self) -> Path | None:
        return None


class RegistryError(ConfigError):
    """Collector registry validation error."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RegistryError(message)


def load_registry(path: Path, collectors_root: Path) -> dict[str, CollectorDefinition]:
    """Load and validate the allowlisted collector registry."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"Unable to load collector registry: {exc}") from exc
    if not isinstance(data, dict):
        raise RegistryError("Collector registry must be an object")
    collectors = data.get("collectors")
    if not isinstance(collectors, list):
        raise RegistryError("collectors must be an array")

    root = collectors_root.resolve()
    by_id: dict[str, CollectorDefinition] = {}
    for item in collectors:
        if not isinstance(item, dict):
            raise RegistryError("Each collector definition must be an object")
        collector = _parse_collector(item, root)
        if collector.id in by_id:
            raise RegistryError(f"Duplicate collector ID: {collector.id}")
        by_id[collector.id] = collector
    return by_id


def _parse_collector(item: dict[str, Any], collectors_root: Path) -> CollectorDefinition:
    required = [
        "id",
        "platform",
        "script_path",
        "category",
        "profile",
        "mandatory",
        "volatility_order",
        "privilege",
        "timeout_seconds",
        "maximum_output_bytes",
        "required_commands",
        "description",
        "sensitive_fields",
        "interpreter",
    ]
    missing = [key for key in required if key not in item]
    _require(not missing, f"Collector missing fields: {missing}")

    collector_id = item["id"]
    _require(isinstance(collector_id, str) and bool(collector_id), "collector id must be string")

    platform = item["platform"]
    _require(platform in {"windows", "linux"}, f"Invalid platform for {collector_id}")

    script_path = item["script_path"]
    _require(isinstance(script_path, str) and bool(script_path), "script_path must be string")
    _require(
        not _looks_absolute_path(script_path),
        f"Absolute collector path rejected: {script_path}",
    )
    _require(".." not in Path(script_path).parts, f"Traversal in collector path: {script_path}")

    resolved = (collectors_root / script_path).resolve()
    try:
        resolved.relative_to(collectors_root.resolve())
    except ValueError as exc:
        raise RegistryError(f"Collector path outside collectors directory: {script_path}") from exc
    _require(resolved.is_file(), f"Collector script not found: {script_path}")

    profile = item["profile"]
    _require(profile in {"minimal", "standard"}, f"Invalid profile for {collector_id}")

    privilege = item["privilege"]
    _require(privilege in ALLOWED_PRIVILEGES, f"Invalid privilege for {collector_id}")

    interpreter = item["interpreter"]
    _require(interpreter in ALLOWED_INTERPRETERS, f"Unsupported interpreter for {collector_id}")

    timeout = item["timeout_seconds"]
    _require(isinstance(timeout, int) and not isinstance(timeout, bool), "timeout must be int")
    _require(0 < timeout <= MAX_TIMEOUT_SECONDS, f"Invalid timeout for {collector_id}")

    max_bytes = item["maximum_output_bytes"]
    _require(
        isinstance(max_bytes, int) and not isinstance(max_bytes, bool), "max bytes must be int"
    )
    _require(0 < max_bytes <= MAX_OUTPUT_BYTES, f"Excessive output limit for {collector_id}")

    volatility = item["volatility_order"]
    _require(
        isinstance(volatility, int) and volatility > 0, "volatility_order must be positive int"
    )

    required_commands = item["required_commands"]
    _require(isinstance(required_commands, list), "required_commands must be list")
    _require(all(isinstance(cmd, str) for cmd in required_commands), "required_commands strings")

    sensitive = item["sensitive_fields"]
    _require(isinstance(sensitive, list), "sensitive_fields must be list")

    # Reject arbitrary command argument bags in registry.
    _require("arguments" not in item, f"Arbitrary arguments not allowed for {collector_id}")
    _require("command" not in item, f"Arbitrary command not allowed for {collector_id}")

    return CollectorDefinition(
        id=collector_id,
        platform=platform,
        script_path=script_path.replace("\\", "/"),
        category=str(item["category"]),
        profile=profile,
        mandatory=bool(item["mandatory"]),
        volatility_order=volatility,
        privilege=privilege,
        timeout_seconds=timeout,
        maximum_output_bytes=max_bytes,
        required_commands=list(required_commands),
        description=str(item["description"]),
        sensitive_fields=[str(field) for field in sensitive],
        interpreter=interpreter,
        optional_in_profiles=list(item.get("optional_in_profiles") or []),
    )


def select_collectors(
    registry: dict[str, CollectorDefinition],
    *,
    platform: str,
    profile: str,
    include_optional: bool = False,
    collector_ids: list[str] | None = None,
) -> list[CollectorDefinition]:
    """Select allowlisted collectors for a platform/profile, ordered by volatility."""
    if collector_ids is not None:
        selected: list[CollectorDefinition] = []
        for collector_id in collector_ids:
            if collector_id not in registry:
                raise RegistryError(f"Unknown collector ID: {collector_id}")
            collector = registry[collector_id]
            if collector.platform != platform:
                raise RegistryError(
                    f"Collector {collector_id} platform mismatch: {collector.platform} != {platform}"
                )
            selected.append(collector)
        return sorted(selected, key=lambda item: (item.volatility_order, item.id))

    profile_rank = {"minimal": 0, "standard": 1}
    wanted_rank = profile_rank[profile]
    selected = []
    for collector in registry.values():
        if collector.platform != platform:
            continue
        collector_rank = profile_rank[collector.profile]
        if collector_rank > wanted_rank:
            continue
        if not collector.mandatory and not include_optional:
            # optional collectors still included when their profile matches unless
            # marked optional-only and include_optional is false.
            if collector.profile == "standard" and profile == "minimal":
                continue
            if (
                "optional" in collector.optional_in_profiles
                and profile in collector.optional_in_profiles
            ):
                continue
        selected.append(collector)
    return sorted(selected, key=lambda item: (item.volatility_order, item.id))


def resolve_collector_script(collector: CollectorDefinition, collectors_root: Path) -> Path:
    """Resolve and re-validate an allowlisted collector script path."""
    resolved = (collectors_root / collector.script_path).resolve()
    try:
        resolved.relative_to(collectors_root.resolve())
    except ValueError as exc:
        raise RegistryError(
            f"Collector path outside collectors directory: {collector.script_path}"
        ) from exc
    if not resolved.is_file():
        raise RegistryError(f"Collector script missing: {collector.script_path}")
    return resolved
