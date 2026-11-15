"""Orkiestracja bezpiecznego przeplywu pasywnej analizy."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from config import AnalysisConfig
from connections import correlate_iocs, parse_connection_log
from errors import InputFileError
from fileio import read_script
from ioc import extract_iocs, merge_iocs
from models import AnalysisResult, Finding, SourceMetadata
from obfuscation import deobfuscate, detect_obfuscation
from reporting import write_reports
from reputation import check_reputation
from rules import scan_suspicious
from timing import get_timestamp


def merge_findings(
    original: tuple[Finding, ...],
    transformed: tuple[Finding, ...],
) -> tuple[Finding, ...]:
    """Scala detekcje, oznaczajac te widoczne dopiero po defuskacji."""

    merged = list(original)
    seen = {(item.rule_id, item.line, item.excerpt) for item in original}
    for item in transformed:
        key = (item.rule_id, item.line, item.excerpt)
        if key in seen:
            continue
        seen.add(key)
        merged.append(replace(item, tags=tuple(sorted(set(item.tags) | {"deobfuscated"}))))
    return tuple(sorted(merged, key=lambda item: (item.line, item.rule_id, item.excerpt)))


def analyze_file(path: Path | str, config: AnalysisConfig | None = None) -> AnalysisResult:
    """Uruchamia wszystkie lokalne etapy analizy, nigdy nie wykonujac skryptu."""

    settings = config or AnalysisConfig()
    started = get_timestamp(settings.ntp_server, settings.request_timeout)
    source = read_script(path, settings.max_file_size)
    warnings: list[str] = []
    if settings.ntp_server and not started.synchronized:
        warnings.append("Synchronizacja NTP nie powiodla sie; uzyto zegara systemowego")

    signals = detect_obfuscation(source.text)
    transformed_text, transformations = deobfuscate(source.text)
    original_findings = scan_suspicious(source.text, source.language)
    transformed_findings = (
        scan_suspicious(transformed_text, source.language) if transformations else ()
    )
    findings = merge_findings(original_findings, transformed_findings)
    original_iocs = extract_iocs(source.text, "original")
    transformed_iocs = (
        extract_iocs(transformed_text, "deobfuscated") if transformations else ()
    )
    iocs = merge_iocs(original_iocs, transformed_iocs)

    records = []
    for log_path in settings.connection_logs:
        try:
            records.extend(parse_connection_log(log_path))
        except InputFileError as error:
            warnings.append(str(error))
    connection_matches = correlate_iocs(iocs, tuple(records))

    reputation = ()
    if settings.reputation_provider and settings.reputation_api_key:
        reputation = check_reputation(
            iocs,
            settings.reputation_provider,
            settings.reputation_api_key,
            settings.request_timeout,
        )
        if any(item.status.startswith("error:") for item in reputation):
            warnings.append("Co najmniej jedno zapytanie reputacyjne zakonczylo sie bledem")

    completed = get_timestamp(settings.ntp_server, settings.request_timeout)
    if settings.ntp_server and not completed.synchronized and not any("NTP" in item for item in warnings):
        warnings.append("Synchronizacja NTP nie powiodla sie; uzyto zegara systemowego")
    return AnalysisResult(
        schema_version="1.0",
        source=SourceMetadata(
            path=str(source.path),
            name=source.path.name,
            size_bytes=len(source.raw),
            modified_at_utc=source.modified_at_utc,
        ),
        language=source.language,
        hashes=source.hashes,
        started_at=started,
        completed_at=completed,
        findings=findings,
        obfuscation_signals=signals,
        transformations=transformations,
        iocs=iocs,
        connection_matches=connection_matches,
        reputation=reputation,
        warnings=tuple(warnings),
        deobfuscated_text=transformed_text if transformations else None,
    )


def analyze_and_write(
    path: Path | str,
    config: AnalysisConfig | None = None,
) -> tuple[AnalysisResult, tuple[Path, ...]]:
    """Analizuje plik i zapisuje wersjonowane artefakty w skonfigurowanym katalogu."""

    settings = config or AnalysisConfig()
    result = analyze_file(path, settings)
    outputs = write_reports(result, settings.output_dir, settings.report_formats)
    return result, outputs
