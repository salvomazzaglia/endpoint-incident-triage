"""Configuration loading and validation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ALLOWED_PROFILES = frozenset({"minimal", "standard"})
ALLOWED_PLATFORMS = frozenset({"windows", "linux", "auto"})
MAX_TIMEOUT_SECONDS = 600
MAX_OUTPUT_BYTES = 50 * 1024 * 1024
KNOWN_TOP_KEYS = frozenset(
    {
        "schema_version",
        "tool",
        "defaults",
        "privacy",
        "collection",
        "safety",
        "paths",
        "profiles",
        "synthetic",
    }
)
# "collection" and "profiles"/"synthetic" are informational metadata keys.


class ConfigError(ValueError):
    """Invalid configuration."""


@dataclass(slots=True)
class CollectionDefaults:
    profile: str = "minimal"
    platform: str = "auto"
    since_hours: int = 24
    include_optional: bool = False
    include_command_lines: bool = False
    include_event_messages: bool = False
    collector_timeout_seconds: int = 120
    maximum_output_bytes: int = 5 * 1024 * 1024
    max_event_count: int = 200
    max_recent_files: int = 50
    max_recent_file_depth: int = 2
    max_hash_file_bytes: int = 1_048_576


@dataclass(slots=True)
class PrivacyDefaults:
    report_mode: str = "masked"
    hash_salt_env: str = "EIT_HASH_SALT"


@dataclass(slots=True)
class SafetyDefaults:
    refuse_overwrite: bool = True
    refuse_system_sensitive_output: bool = True
    refuse_output_inside_collectors: bool = True
    never_self_elevate: bool = True
    allow_live_collection: bool = False


@dataclass(slots=True)
class AppConfig:
    schema_version: str
    tool_name: str
    defaults: CollectionDefaults
    privacy: PrivacyDefaults
    safety: SafetyDefaults
    registry_path: Path
    profiles_path: Path
    rules_path: Path
    collectors_root: Path
    raw: dict[str, Any] = field(default_factory=dict)
    config_path: Path | None = None


def _require_dict(data: Any, label: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ConfigError(f"{label} must be an object")
    return data


def _positive_int(value: Any, label: str, *, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{label} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{label} exceeds maximum allowed value {maximum}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Unable to read config: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {path}: {exc}") from exc
    return _require_dict(payload, str(path))


def validate_config_dict(data: dict[str, Any], *, base_dir: Path) -> AppConfig:
    unknown = set(data) - KNOWN_TOP_KEYS
    if unknown:
        raise ConfigError(f"Unknown config keys: {sorted(unknown)}")

    schema_version = data.get("schema_version")
    if schema_version != "1.0.0":
        raise ConfigError("schema_version must be 1.0.0")

    tool = _require_dict(data.get("tool", {}), "tool")
    tool_name = tool.get("name", "endpoint-incident-triage")
    if not isinstance(tool_name, str) or not tool_name:
        raise ConfigError("tool.name must be a non-empty string")

    defaults_raw = _require_dict(data.get("defaults", {}), "defaults")
    profile = defaults_raw.get("profile", "minimal")
    if profile not in ALLOWED_PROFILES:
        raise ConfigError(f"Invalid profile: {profile}")
    platform = defaults_raw.get("platform", "auto")
    if platform not in ALLOWED_PLATFORMS:
        raise ConfigError(f"Invalid platform: {platform}")

    defaults = CollectionDefaults(
        profile=profile,
        platform=platform,
        since_hours=_positive_int(defaults_raw.get("since_hours", 24), "defaults.since_hours"),
        include_optional=bool(defaults_raw.get("include_optional", False)),
        include_command_lines=bool(defaults_raw.get("include_command_lines", False)),
        include_event_messages=bool(defaults_raw.get("include_event_messages", False)),
        collector_timeout_seconds=_positive_int(
            defaults_raw.get("collector_timeout_seconds", 120),
            "defaults.collector_timeout_seconds",
            maximum=MAX_TIMEOUT_SECONDS,
        ),
        maximum_output_bytes=_positive_int(
            defaults_raw.get("maximum_output_bytes", 5 * 1024 * 1024),
            "defaults.maximum_output_bytes",
            maximum=MAX_OUTPUT_BYTES,
        ),
        max_event_count=_positive_int(
            defaults_raw.get("max_event_count", 200), "defaults.max_event_count"
        ),
        max_recent_files=_positive_int(
            defaults_raw.get("max_recent_files", 50), "defaults.max_recent_files"
        ),
        max_recent_file_depth=_positive_int(
            defaults_raw.get("max_recent_file_depth", 2), "defaults.max_recent_file_depth"
        ),
        max_hash_file_bytes=_positive_int(
            defaults_raw.get("max_hash_file_bytes", 1_048_576),
            "defaults.max_hash_file_bytes",
            maximum=MAX_OUTPUT_BYTES,
        ),
    )

    privacy_raw = _require_dict(data.get("privacy", {}), "privacy")
    report_mode = privacy_raw.get("report_mode", "masked")
    if report_mode not in {"masked", "hashed", "full"}:
        raise ConfigError(f"Invalid privacy.report_mode: {report_mode}")
    privacy = PrivacyDefaults(
        report_mode=report_mode,
        hash_salt_env=str(privacy_raw.get("hash_salt_env", "EIT_HASH_SALT")),
    )

    safety_raw = _require_dict(data.get("safety", {}), "safety")
    safety = SafetyDefaults(
        refuse_overwrite=bool(safety_raw.get("refuse_overwrite", True)),
        refuse_system_sensitive_output=bool(safety_raw.get("refuse_system_sensitive_output", True)),
        refuse_output_inside_collectors=bool(
            safety_raw.get("refuse_output_inside_collectors", True)
        ),
        never_self_elevate=bool(safety_raw.get("never_self_elevate", True)),
        allow_live_collection=bool(safety_raw.get("allow_live_collection", False)),
    )

    paths_raw = _require_dict(data.get("paths", {}), "paths")

    def resolve_path(key: str, default: str) -> Path:
        value = paths_raw.get(key, default)
        if not isinstance(value, str) or not value:
            raise ConfigError(f"paths.{key} must be a non-empty string")
        if Path(value).is_absolute():
            raise ConfigError(f"paths.{key} must be relative: {value}")
        if ".." in Path(value).parts:
            raise ConfigError(f"paths.{key} must not contain traversal: {value}")
        return (base_dir / value).resolve()

    registry_path = resolve_path("collector_registry", "config/collector-registry.json")
    profiles_path = resolve_path("collection_profiles", "config/collection-profiles.json")
    rules_path = resolve_path("triage_rules", "config/triage-rules.json")
    collectors_root = resolve_path("collectors_root", "collectors")

    return AppConfig(
        schema_version=schema_version,
        tool_name=tool_name,
        defaults=defaults,
        privacy=privacy,
        safety=safety,
        registry_path=registry_path,
        profiles_path=profiles_path,
        rules_path=rules_path,
        collectors_root=collectors_root,
        raw=data,
        config_path=None,
    )


def load_config(path: str | Path) -> AppConfig:
    """Load and validate a configuration file."""
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Config file not found: {config_path}")
    # Base directory is the repository root (parent of config/).
    base_dir = config_path.resolve().parent.parent
    if config_path.parent.name != "config":
        base_dir = config_path.resolve().parent
    data = load_json(config_path)
    config = validate_config_dict(data, base_dir=base_dir)
    config.config_path = config_path.resolve()
    return config


def validate_all_configs(repo_root: Path) -> list[str]:
    """Validate default and demo configuration files; return messages."""
    messages: list[str] = []
    for relative in ("config/default.config.json", "config/demo.config.json"):
        path = repo_root / relative
        config = load_config(path)
        messages.append(f"OK {relative} profile={config.defaults.profile}")
    return messages
