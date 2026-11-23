"""Modele danych wymieniane przez moduly analizatora."""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class Hashes:
    sha256: str
    sha1: str
    md5: str


@dataclass(frozen=True, slots=True)
class ScriptInput:
    path: Path
    raw: bytes
    text: str
    encoding: str
    language: str
    hashes: Hashes
    modified_at_utc: str


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    line: int
    excerpt: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EngineRun:
    engine: str
    representation: str
    status: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ObfuscationSignal:
    kind: str
    confidence: str
    line: int
    detail: str


@dataclass(frozen=True, slots=True)
class Transformation:
    kind: str
    line: int
    original: str
    transformed: str


@dataclass(frozen=True, slots=True)
class IOC:
    kind: str
    value: str
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConnectionRecord:
    timestamp: str | None
    address: str
    log_source: str
    raw: str
    event_type: str = "mentioned"
    process_key: str | None = None


@dataclass(frozen=True, slots=True)
class ConnectionMatch:
    ioc_kind: str
    ioc_value: str
    timestamp: str | None
    log_source: str
    raw: str
    event_type: str = "mentioned"
    process_key: str | None = None
    script_related: bool = False


@dataclass(frozen=True, slots=True)
class ConnectionCheck:
    """Wynik sprawdzenia jednego IOC w dostepnych logach polaczen."""

    ioc_kind: str
    ioc_value: str
    status: str
    match_count: int
    checked_log_count: int
    evidence_types: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HistoryEvent:
    event_type: str
    timestamp: str | None
    log_source: str
    address: str = ""
    image: str = ""
    command_line: str = ""
    script_path: str = ""
    script_sha256: str = ""
    cwd: str = ""
    process_key: str | None = None
    raw: str = ""
    argv: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutionMatch:
    timestamp: str | None
    log_source: str
    identity: str
    detail: str
    process_key: str | None = None


@dataclass(frozen=True, slots=True)
class ExecutionCheck:
    status: str = "not-checked"
    checked_log_count: int = 0
    matches: tuple[ExecutionMatch, ...] = ()


@dataclass(frozen=True, slots=True)
class HistorySource:
    name: str
    status: str
    event_count: int
    network_event_count: int = 0
    execution_event_count: int = 0
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ReputationResult:
    provider: str
    ioc_kind: str
    ioc_value: str
    status: str
    malicious_count: int | None
    reference: str | None


@dataclass(frozen=True, slots=True)
class TimestampInfo:
    iso_utc: str
    source: str
    ntp_server: str | None = None
    synchronized: bool = False


@dataclass(frozen=True, slots=True)
class SourceMetadata:
    path: str
    name: str
    size_bytes: int
    modified_at_utc: str


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    schema_version: str
    source: SourceMetadata
    language: str
    hashes: Hashes
    started_at: TimestampInfo
    completed_at: TimestampInfo
    findings: tuple[Finding, ...]
    obfuscation_signals: tuple[ObfuscationSignal, ...]
    transformations: tuple[Transformation, ...]
    iocs: tuple[IOC, ...]
    connection_checks: tuple[ConnectionCheck, ...]
    connection_matches: tuple[ConnectionMatch, ...]
    reputation: tuple[ReputationResult, ...]
    warnings: tuple[str, ...]
    deobfuscated_text: str | None
    execution_check: ExecutionCheck = ExecutionCheck()
    history_sources: tuple[HistorySource, ...] = ()
    engine_runs: tuple[EngineRun, ...] = ()


def to_primitive(value: Any) -> Any:
    """Konwertuje modele na struktury bezpieczne dla serializacji JSON."""

    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: to_primitive(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        normalized = value.astimezone(timezone.utc)
        return normalized.isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_primitive(item) for item in value]
    return value
