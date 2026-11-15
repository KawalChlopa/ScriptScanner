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


@dataclass(frozen=True, slots=True)
class ConnectionMatch:
    ioc_kind: str
    ioc_value: str
    timestamp: str | None
    log_source: str
    raw: str


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
    connection_matches: tuple[ConnectionMatch, ...]
    reputation: tuple[ReputationResult, ...]
    warnings: tuple[str, ...]
    deobfuscated_text: str | None


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
