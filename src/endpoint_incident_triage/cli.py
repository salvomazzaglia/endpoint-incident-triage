"""Command-line interface for endpoint-incident-triage."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from endpoint_incident_triage import TOOL_NAME, __version__
from endpoint_incident_triage.case import (
    create_case_metadata,
    initialize_case_package,
    write_case_metadata_files,
    write_collector_artifact,
    write_collector_execution_log,
    write_findings_json,
)
from endpoint_incident_triage.collector_registry import (
    RegistryError,
    load_registry,
    select_collectors,
)
from endpoint_incident_triage.collector_runner import run_collectors
from endpoint_incident_triage.config import ConfigError, load_config, validate_all_configs
from endpoint_incident_triage.console import (
    print_collection_plan,
    print_report_summary,
    print_verification_summary,
)
from endpoint_incident_triage.custody import append_record, write_ledger
from endpoint_incident_triage.evidence_paths import (
    PathValidationError,
    is_system_sensitive_path,
    refuse_output_inside_source,
)
from endpoint_incident_triage.exit_codes import (
    EXIT_ERROR,
    EXIT_FAILURE,
    EXIT_OK,
    EXIT_PARTIAL,
)
from endpoint_incident_triage.findings import evaluate_findings, highest_severity
from endpoint_incident_triage.html_report import write_html_report
from endpoint_incident_triage.json_report import build_triage_report, write_json_report
from endpoint_incident_triage.manifest import (
    build_manifest,
    compute_manifest_document_hash,
    write_manifest,
    write_sha256sums,
)
from endpoint_incident_triage.package import PackageError, create_zip_package
from endpoint_incident_triage.platform import resolve_platform
from endpoint_incident_triage.rules import RulesError, load_rules
from endpoint_incident_triage.statuses import (
    CollectorStatus,
    FindingSeverity,
    PrivacyMode,
    SourceMode,
)
from endpoint_incident_triage.timeline import build_timeline, write_timeline_jsonl
from endpoint_incident_triage.verification import verify_package

LIVE_WARNING = """\
WARNING: Live collection is minimally invasive but NOT perfectly read-only.
Running collectors can affect process state, memory, event logs, file-access
metadata, caches, command history, endpoint security telemetry, and timing.
This toolkit does not make a forensic image, acquire volatile memory, or
guarantee legal admissibility. Proceed only with explicit authorization.
"""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"{TOOL_NAME}: cross-platform non-destructive endpoint incident triage "
            "with evidence-integrity verification."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="Display what would be collected (no live execution)")
    plan.add_argument("--config", required=True)
    plan.add_argument("--profile", choices=("minimal", "standard"), required=True)
    plan.add_argument("--platform", choices=("windows", "linux", "auto"), default="auto")
    plan.add_argument("--collectors", nargs="*", default=None)
    plan.add_argument("--since-hours", type=int, default=None)
    plan.add_argument("--include-optional", action="store_true")
    plan.add_argument("--verbose", action="store_true")

    collect = sub.add_parser(
        "collect", help="Authorized live collection (requires acknowledgement)"
    )
    collect.add_argument("--acknowledge-live-collection", action="store_true")
    collect.add_argument("--case-id", required=True)
    collect.add_argument("--output-directory", required=True)
    collect.add_argument("--profile", choices=("minimal", "standard"), required=True)
    collect.add_argument("--config", default="config/default.config.json")
    collect.add_argument("--platform", choices=("windows", "linux", "auto"), default="auto")
    collect.add_argument("--authorization-reference", default="AUTH-UNSPECIFIED")
    collect.add_argument("--operator-label", default="OPERATOR")
    collect.add_argument("--collection-reason", default="Authorized endpoint triage")
    collect.add_argument("--target-label", default="TARGET")
    collect.add_argument("--since-hours", type=int, default=None)
    collect.add_argument("--include-optional", action="store_true")
    collect.add_argument("--include-command-lines", action="store_true")
    collect.add_argument("--include-event-messages", action="store_true")
    collect.add_argument("--strict", action="store_true")
    collect.add_argument("--verbose", action="store_true")

    synth = sub.add_parser(
        "collect-synthetic",
        help="Generate evidence package from synthetic fixtures only",
    )
    synth.add_argument("--case-id", required=True)
    synth.add_argument("--platform", choices=("windows", "linux"), required=True)
    synth.add_argument("--output-directory", required=True)
    synth.add_argument("--config", default="config/demo.config.json")
    synth.add_argument("--profile", choices=("minimal", "standard"), default="standard")
    synth.add_argument("--include-optional", action="store_true", default=True)
    synth.add_argument("--strict", action="store_true")
    synth.add_argument("--verbose", action="store_true")

    verify = sub.add_parser("verify", help="Verify a directory or ZIP evidence package")
    verify.add_argument("--package", required=True)
    verify.add_argument("--verbose", action="store_true")

    report = sub.add_parser("report", help="Generate JSON/HTML reports from a verified package")
    report.add_argument("--package", required=True)
    report.add_argument("--output-directory", required=True)
    report.add_argument("--format", choices=("json", "html", "all"), default="all")
    report.add_argument("--privacy-mode", choices=("masked", "hashed", "full"), default="masked")
    report.add_argument("--hash-salt-env", default="EIT_HASH_SALT")
    report.add_argument("--include-low-severity", action="store_true")
    report.add_argument("--fail-on-high-finding", action="store_true")
    report.add_argument("--config", default="config/demo.config.json")
    report.add_argument("--verbose", action="store_true")

    package_cmd = sub.add_parser("package", help="Create a ZIP from an evidence-package directory")
    package_cmd.add_argument("--package", required=True)
    package_cmd.add_argument("--output", required=True)

    list_cmd = sub.add_parser("list-collectors", help="List allowlisted collectors")
    list_cmd.add_argument("--config", required=True)
    list_cmd.add_argument("--platform", choices=("windows", "linux", "auto"), default="auto")

    validate = sub.add_parser("validate-config", help="Validate configuration files and rules")
    validate.add_argument("--config", default=None)
    validate.add_argument("--repo-root", default=None)

    sub.add_parser("version", help="Print version")
    return parser


def _exit_from_results(
    results: list[Any],
    *,
    strict: bool = False,
) -> int:
    statuses = [item.status for item in results]
    mandatory_failed = any(status == CollectorStatus.ERROR for status in statuses)
    if mandatory_failed:
        return EXIT_FAILURE
    partialish = {
        CollectorStatus.PARTIAL,
        CollectorStatus.UNAVAILABLE,
    }
    if any(status in partialish for status in statuses):
        if strict:
            return EXIT_FAILURE
        return EXIT_PARTIAL
    return EXIT_OK


def _cmd_version(_: argparse.Namespace) -> int:
    print(f"{TOOL_NAME} {__version__}")
    return EXIT_OK


def _cmd_validate_config(args: argparse.Namespace) -> int:
    try:
        if args.config:
            config = load_config(args.config)
            registry = load_registry(config.registry_path, config.collectors_root)
            rules = load_rules(config.rules_path)
            print(f"Configuration OK: {args.config}")
            print(f"Collectors: {len(registry)}")
            print(f"Rules: {len(rules)}")
            return EXIT_OK
        root = Path(args.repo_root) if args.repo_root else _repo_root()
        for message in validate_all_configs(root):
            print(message)
        config = load_config(root / "config" / "default.config.json")
        load_registry(config.registry_path, config.collectors_root)
        load_rules(config.rules_path)
        print("All configuration files and rules validated.")
        return EXIT_OK
    except (ConfigError, RegistryError, RulesError) as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        return EXIT_ERROR


def _cmd_list_collectors(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
        registry = load_registry(config.registry_path, config.collectors_root)
        platform = resolve_platform(args.platform)
    except (ConfigError, RegistryError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    rows = [
        collector
        for collector in sorted(
            registry.values(), key=lambda item: (item.platform, item.volatility_order)
        )
        if args.platform == "auto" or collector.platform == platform.value
    ]
    print(
        f"{'ID':<36} {'Platform':<8} {'Category':<16} {'Profile':<10} "
        f"{'Vol':>3} {'Priv':<18} {'Mand':<5} {'Timeout':>7}"
    )
    for collector in rows:
        print(
            f"{collector.id:<36} {collector.platform:<8} {collector.category:<16} "
            f"{collector.profile:<10} {collector.volatility_order:>3} "
            f"{collector.privilege:<18} {collector.mandatory!s:<5} "
            f"{collector.timeout_seconds:>7}"
        )
        if collector.required_commands:
            print(f"  commands: {', '.join(collector.required_commands)}")
    return EXIT_OK


def _cmd_plan(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
        registry = load_registry(config.registry_path, config.collectors_root)
        platform = resolve_platform(args.platform)
        selected = select_collectors(
            registry,
            platform=platform.value,
            profile=args.profile,
            include_optional=args.include_optional,
            collector_ids=args.collectors,
        )
    except (ConfigError, RegistryError, RuntimeError, ValueError) as exc:
        print(f"Plan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    since = args.since_hours or config.defaults.since_hours
    print_collection_plan(
        selected, platform=platform.value, profile=args.profile, since_hours=since
    )
    print("No live collectors were executed.")
    return EXIT_OK


def _assemble_package(
    *,
    config_path: str,
    case_id: str,
    platform: str,
    profile: str,
    output_directory: str,
    source_mode: SourceMode,
    authorization_reference: str,
    operator_label: str,
    collection_reason: str,
    target_label: str,
    include_optional: bool,
    include_command_lines: bool,
    include_event_messages: bool,
    since_hours: int | None,
    prefer_fixture: bool,
    stamp: str | None = None,
) -> tuple[Path, int]:
    config = load_config(config_path)
    registry = load_registry(config.registry_path, config.collectors_root)
    rules = load_rules(config.rules_path)
    selected = select_collectors(
        registry,
        platform=platform,
        profile=profile,
        include_optional=include_optional,
    )

    output_parent = Path(output_directory)
    if config.safety.refuse_system_sensitive_output and is_system_sensitive_path(output_parent):
        raise PathValidationError(f"Unsafe output directory: {output_parent}")
    if config.safety.refuse_output_inside_collectors:
        refuse_output_inside_source(
            output_parent,
            [config.collectors_root, _repo_root() / "src", _repo_root() / "collectors"],
        )

    stamp_value = stamp or _stamp()
    limitations = [
        "Live-response collection is non-destructive and minimally invasive, not perfectly read-only.",
        "This package is not a forensic image and does not include volatile memory.",
        "A valid SHA-256 manifest proves consistency with the recorded manifest, not legal provenance.",
        "The custody ledger is tamper-evident, not tamper-proof.",
        "Heuristic findings require analyst review and are not malware verdicts.",
    ]
    if source_mode == SourceMode.SYNTHETIC:
        limitations.append("SYNTHETIC DEMONSTRATION DATA — no real endpoint was inspected.")

    metadata = create_case_metadata(
        case_id=case_id,
        authorization_reference=authorization_reference,
        operator_label=operator_label,
        collection_reason=collection_reason,
        target_label=target_label,
        platform=platform,
        profile=profile,
        source_mode=source_mode,
        limitations=limitations,
    )
    ctx = initialize_case_package(
        output_parent,
        case_id=case_id,
        stamp=stamp_value,
        metadata=metadata,
        actor_label=operator_label,
    )
    append_record(
        ctx.custody_ledger,
        event_type="collection_started",
        package_id=ctx.package_id,
        actor_label=operator_label,
        action="start_collection",
        details={"profile": profile, "platform": platform, "source_mode": source_mode.value},
    )

    results, logs = run_collectors(
        selected,
        config.collectors_root,
        platform=platform,
        source_mode=source_mode,
        include_command_lines=include_command_lines,
        include_event_messages=include_event_messages,
        since_hours=since_hours or config.defaults.since_hours,
        prefer_fixture=prefer_fixture,
    )

    for result in results:
        event = {
            CollectorStatus.COLLECTED: "collector_completed",
            CollectorStatus.PARTIAL: "collector_partial",
            CollectorStatus.UNAVAILABLE: "collector_unavailable",
            CollectorStatus.ERROR: "collector_error",
            CollectorStatus.SKIPPED: "collector_completed",
        }.get(result.status, "collector_completed")
        append_record(
            ctx.custody_ledger,
            event_type="collector_started",
            package_id=ctx.package_id,
            actor_label=operator_label,
            action="start_collector",
            details={"collector_id": result.collector_id},
        )
        append_record(
            ctx.custody_ledger,
            event_type=event,
            package_id=ctx.package_id,
            actor_label=operator_label,
            action="finish_collector",
            details={
                "collector_id": result.collector_id,
                "status": result.status.value,
                "record_count": result.record_count,
            },
        )
        write_collector_artifact(ctx.layout, result)

    write_collector_execution_log(ctx.layout, logs)
    findings = evaluate_findings(results, rules)
    write_findings_json(ctx.layout, [item.to_dict() for item in findings])
    timeline = build_timeline(results)
    write_timeline_jsonl(ctx.layout["timeline"] / "timeline.jsonl", timeline)

    metadata.completed_at_utc = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_case_metadata_files(ctx.layout, metadata)

    append_record(
        ctx.custody_ledger,
        event_type="collection_completed",
        package_id=ctx.package_id,
        actor_label=operator_label,
        action="complete_collection",
        details={"collectors": len(results), "findings": len(findings)},
    )
    write_ledger(ctx.layout["custody"] / "custody.jsonl", ctx.custody_ledger)

    # Build provisional manifest to obtain a hash for the custody event.
    provisional = build_manifest(ctx.case_dir, package_id=ctx.package_id)
    write_manifest(ctx.layout["manifests"] / "manifest.json", provisional)
    write_sha256sums(ctx.layout["manifests"] / "SHA256SUMS", provisional)
    provisional_hash = compute_manifest_document_hash(ctx.layout["manifests"] / "manifest.json")
    append_record(
        ctx.custody_ledger,
        event_type="manifest_created",
        package_id=ctx.package_id,
        actor_label=operator_label,
        action="create_manifest",
        details={
            "provisional_manifest_sha256": provisional_hash,
            "entry_count": len(provisional.entries),
            "final_hash_location": "metadata/manifest-hash.json",
        },
    )
    write_ledger(ctx.layout["custody"] / "custody.jsonl", ctx.custody_ledger)

    # Final manifest after custody ledger is complete. Do not mutate included files afterward.
    manifest = build_manifest(ctx.case_dir, package_id=ctx.package_id)
    write_manifest(ctx.layout["manifests"] / "manifest.json", manifest)
    write_sha256sums(ctx.layout["manifests"] / "SHA256SUMS", manifest)
    final_hash = compute_manifest_document_hash(ctx.layout["manifests"] / "manifest.json")
    hash_doc = {
        "schema_version": "1.0.0",
        "algorithm": "sha256",
        "manifest_relative_path": "manifests/manifest.json",
        "manifest_sha256": final_hash,
        "generated_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": (
            "Excluded from manifest scope so the recorded hash can reference the final "
            "manifest without self-inclusion. Also recorded in the custody ledger."
        ),
    }
    hash_path = ctx.layout["metadata"] / "manifest-hash.json"
    hash_path.write_text(
        json.dumps(hash_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    exit_code = _exit_from_results(results)
    return ctx.case_dir, exit_code


def _cmd_collect(args: argparse.Namespace) -> int:
    if not args.acknowledge_live_collection:
        print("Live collection requires --acknowledge-live-collection", file=sys.stderr)
        return EXIT_ERROR
    print(LIVE_WARNING)
    if args.include_command_lines:
        print(
            "WARNING: --include-command-lines may capture credentials or tokens in process arguments."
        )
    if args.include_event_messages:
        print("WARNING: --include-event-messages may include personal or sensitive event text.")
    try:
        platform = resolve_platform(args.platform).value
        case_dir, exit_code = _assemble_package(
            config_path=args.config,
            case_id=args.case_id,
            platform=platform,
            profile=args.profile,
            output_directory=args.output_directory,
            source_mode=SourceMode.LIVE,
            authorization_reference=args.authorization_reference,
            operator_label=args.operator_label,
            collection_reason=args.collection_reason,
            target_label=args.target_label,
            include_optional=args.include_optional,
            include_command_lines=args.include_command_lines,
            include_event_messages=args.include_event_messages,
            since_hours=args.since_hours,
            prefer_fixture=False,
        )
    except (ConfigError, RegistryError, RulesError, PathValidationError, OSError) as exc:
        print(f"Collection failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Evidence package created: {case_dir}")
    if args.strict and exit_code == EXIT_PARTIAL:
        return EXIT_FAILURE
    return exit_code


def _cmd_collect_synthetic(args: argparse.Namespace) -> int:
    try:
        case_dir, exit_code = _assemble_package(
            config_path=args.config,
            case_id=args.case_id,
            platform=args.platform,
            profile=args.profile,
            output_directory=args.output_directory,
            source_mode=SourceMode.SYNTHETIC,
            authorization_reference="SYNTHETIC-AUTH",
            operator_label="SYNTHETIC-COLLECTOR",
            collection_reason="Synthetic demonstration collection",
            target_label="SYNTHETIC-ENDPOINT-01",
            include_optional=args.include_optional,
            include_command_lines=False,
            include_event_messages=False,
            since_hours=24,
            prefer_fixture=True,
            stamp="20260805T180000Z",
        )
    except (ConfigError, RegistryError, RulesError, PathValidationError, OSError) as exc:
        print(f"Synthetic collection failed: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return EXIT_ERROR
    print("SYNTHETIC DEMONSTRATION DATA")
    print(
        "This package contains synthetic endpoint-triage data created exclusively "
        "for demonstration, testing, and documentation purposes."
    )
    print(f"Evidence package created: {case_dir}")
    if args.strict and exit_code == EXIT_PARTIAL:
        return EXIT_FAILURE
    return exit_code


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        result = verify_package(Path(args.package))
    except Exception as exc:
        print(f"Verification error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print_verification_summary(result)
    if args.verbose:
        for error in result.errors:
            print(f"ERROR: {error}")
        for warning in result.warnings:
            print(f"WARN: {warning}")
    return EXIT_OK if result.ok else EXIT_FAILURE


def _load_package_components(package_dir: Path) -> dict[str, Any]:
    from endpoint_incident_triage.models import CaseMetadata, CollectorResult, TruncationInfo
    from endpoint_incident_triage.statuses import CollectorStatus, SourceMode
    from endpoint_incident_triage.timeline import read_timeline_jsonl

    case_doc = json.loads((package_dir / "metadata" / "case.json").read_text(encoding="utf-8"))
    metadata = CaseMetadata(
        case_id=case_doc["case_id"],
        collection_id=case_doc["collection_id"],
        authorization_reference=case_doc.get("authorization_reference", ""),
        operator_label=case_doc.get("operator_label", ""),
        collection_reason=case_doc.get("collection_reason", ""),
        target_label=case_doc.get("target_label", ""),
        started_at_utc=case_doc["started_at_utc"],
        completed_at_utc=case_doc.get("completed_at_utc"),
        source_mode=SourceMode(case_doc.get("source_mode", "synthetic")),
        platform=case_doc.get("platform", "unknown"),
        tool_version=case_doc.get("tool_version", __version__),
        profile=case_doc.get("profile", "minimal"),
        limitations=list(case_doc.get("limitations") or []),
    )
    results: list[CollectorResult] = []
    artifacts_root = package_dir / "artifacts"
    if artifacts_root.is_dir():
        for path in sorted(artifacts_root.rglob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            truncation_raw = payload.get("truncation") or {}
            results.append(
                CollectorResult(
                    schema_version=payload.get("schema_version", "1.0.0"),
                    collector_id=payload["collector_id"],
                    platform=payload["platform"],
                    category=payload.get("category", "unknown"),
                    status=CollectorStatus(payload["status"]),
                    started_at_utc=payload["started_at_utc"],
                    completed_at_utc=payload["completed_at_utc"],
                    duration_ms=int(payload.get("duration_ms", 0)),
                    privilege_state=payload.get("privilege_state", "standard"),
                    source_mode=SourceMode(payload.get("source_mode", "synthetic")),
                    record_count=int(payload.get("record_count", 0)),
                    records=list(payload.get("records") or []),
                    warnings=list(payload.get("warnings") or []),
                    errors=list(payload.get("errors") or []),
                    truncation=TruncationInfo(
                        truncated=bool(truncation_raw.get("truncated", False)),
                        reason=truncation_raw.get("reason"),
                        original_bytes=truncation_raw.get("original_bytes"),
                        retained_bytes=truncation_raw.get("retained_bytes"),
                        original_records=truncation_raw.get("original_records"),
                        retained_records=truncation_raw.get("retained_records"),
                    ),
                    sensitive_fields_omitted=list(payload.get("sensitive_fields_omitted") or []),
                    command_provenance=list(payload.get("command_provenance") or []),
                    collector_version=payload.get("collector_version", "1.0.0"),
                    exit_code=payload.get("exit_code"),
                )
            )
    findings_path = package_dir / "findings" / "findings.json"
    findings_payload: list[Any] = []
    if findings_path.is_file():
        findings_payload = (
            json.loads(findings_path.read_text(encoding="utf-8")).get("findings") or []
        )
    timeline_path = package_dir / "timeline" / "timeline.jsonl"
    timeline = read_timeline_jsonl(timeline_path) if timeline_path.is_file() else []
    package_id = package_dir.name
    return {
        "metadata": metadata,
        "results": results,
        "findings_payload": findings_payload,
        "timeline": timeline,
        "package_id": package_id,
    }


def _cmd_report(args: argparse.Namespace) -> int:
    package_path = Path(args.package)
    try:
        verification = verify_package(package_path)
    except Exception as exc:
        print(f"Unable to verify package before report: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if not verification.ok:
        print("Package verification failed; refusing to generate report.", file=sys.stderr)
        print_verification_summary(verification)
        return EXIT_FAILURE

    # Resolve directory package (ZIP extracted by verify temporarily — re-open dir or extract again)
    work_dir = package_path
    temp_dir = None
    if package_path.is_file() and package_path.suffix.lower() == ".zip":
        import tempfile
        import zipfile

        temp_dir = Path(tempfile.mkdtemp(prefix="eit-report-"))
        with zipfile.ZipFile(package_path, "r") as archive:
            archive.extractall(temp_dir)
        # Find case root
        candidates = [path for path in temp_dir.iterdir() if path.is_dir()]
        work_dir = candidates[0] if len(candidates) == 1 else temp_dir

    try:
        if args.privacy_mode == "full":
            print(
                "WARNING: Privacy mode FULL may include sensitive identifiers. "
                "Do not use for public samples."
            )
        components = _load_package_components(work_dir)
        config = load_config(args.config)
        rules = load_rules(config.rules_path)
        findings = evaluate_findings(components["results"], rules)
        if not args.include_low_severity:
            findings = [
                item
                for item in findings
                if item.severity
                in {
                    FindingSeverity.MEDIUM,
                    FindingSeverity.HIGH,
                    FindingSeverity.CRITICAL,
                }
            ]

        privacy_mode = PrivacyMode(args.privacy_mode)
        report = build_triage_report(
            package_id=components["package_id"],
            case_metadata=components["metadata"],
            collector_results=components["results"],
            findings=findings,
            timeline_events=components["timeline"],
            synthetic=components["metadata"].source_mode == SourceMode.SYNTHETIC
            or components["package_id"].upper().startswith("CASE-SYNTHETIC"),
            privacy_mode=privacy_mode,
            integrity_status=verification.integrity_status,
            custody_status=verification.custody_status,
            verification_ok=verification.ok,
            limitations=components["metadata"].limitations,
            recommendations=[
                "Review heuristic findings with an authorized analyst.",
                "Preserve the evidence package under organizational custody procedures.",
                "Do not treat a successful collection as proof that an endpoint is clean.",
            ],
            hash_salt_env=args.hash_salt_env,
        )
        output_dir = Path(args.output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        paths: list[str] = []
        formats = {"json", "html"} if args.format == "all" else {args.format}
        if "json" in formats:
            json_path = output_dir / "triage-report.json"
            write_json_report(json_path, report)
            paths.append(str(json_path))
        if "html" in formats:
            html_path = output_dir / "triage-report.html"
            write_html_report(html_path, report)
            paths.append(str(html_path))
        print_report_summary(report, paths)
        if args.fail_on_high_finding:
            top = highest_severity(findings)
            if top in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}:
                print("Policy exit: High/Critical findings present (--fail-on-high-finding).")
                return EXIT_FAILURE
        return EXIT_OK
    except Exception as exc:
        print(f"Report generation failed: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return EXIT_ERROR
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)


def _cmd_package(args: argparse.Namespace) -> int:
    try:
        result = create_zip_package(Path(args.package), Path(args.output))
    except (PackageError, PathValidationError, OSError) as exc:
        print(f"Packaging failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"ZIP created: {result.zip_path}")
    print(f"SHA-256: {result.sha256}")
    print(f"Checksum file: {result.sha256_path}")
    print("ZIP is not encrypted and does not provide confidentiality.")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "version": _cmd_version,
        "validate-config": _cmd_validate_config,
        "list-collectors": _cmd_list_collectors,
        "plan": _cmd_plan,
        "collect": _cmd_collect,
        "collect-synthetic": _cmd_collect_synthetic,
        "verify": _cmd_verify,
        "report": _cmd_report,
        "package": _cmd_package,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return EXIT_ERROR
    try:
        return handler(args)
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
