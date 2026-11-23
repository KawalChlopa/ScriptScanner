"""Orkiestracja bezpiecznego przeplywu pasywnej analizy."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from config import AnalysisConfig
from connections import assess_connections, correlate_iocs
from engines import scan_engines
from history import assess_execution, collect_system_history, read_history_log, source_summary
from errors import InputFileError
from fileio import read_script
from ioc import extract_iocs, merge_iocs
from models import AnalysisResult, ConnectionRecord, Finding, HistorySource, SourceMetadata
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


def analyze_file(
    path: Path | str,
    config: AnalysisConfig | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> AnalysisResult:
    """Uruchamia wszystkie lokalne etapy analizy, nigdy nie wykonujac skryptu."""

    def announce(step: int, message: str) -> None:
        if progress is not None:
            progress(step, 6, message)

    settings = config or AnalysisConfig()
    started = get_timestamp(settings.ntp_server, settings.request_timeout)
    announce(1, "Odczyt pliku, rozpoznanie jezyka i obliczenie skrotow")
    source = read_script(path, settings.max_file_size)
    warnings: list[str] = []
    if settings.ntp_server and not started.synchronized:
        warnings.append("Synchronizacja NTP nie powiodla sie; uzyto zegara systemowego")

    announce(2, "Wykrywanie obfuskacji i bezpieczna defuskacja kopii")
    signals = detect_obfuscation(source.text)
    transformed_text, transformations = deobfuscate(source.text)
    announce(3, "Sprawdzanie regul i lokalnych silnikow analizy statycznej")
    engine_findings, engine_runs = scan_engines(
        source.text, source.raw, source.language, settings.output_dir, "original",
    )
    original_findings = scan_suspicious(source.text, source.language) + engine_findings
    transformed_findings = ()
    if transformations:
        decoded_findings, decoded_runs = scan_engines(
            transformed_text, transformed_text.encode("utf-8"), source.language,
            settings.output_dir, "deobfuscated",
        )
        engine_runs += decoded_runs
        transformed_findings = scan_suspicious(transformed_text, source.language) + decoded_findings
    findings = merge_findings(original_findings, transformed_findings)
    announce(4, "Ekstrakcja i normalizacja IOC")
    original_iocs = extract_iocs(source.text, "original")
    transformed_iocs = (
        extract_iocs(transformed_text, "deobfuscated") if transformations else ()
    )
    iocs = merge_iocs(original_iocs, transformed_iocs)

    announce(5, "Sprawdzenie historii polaczen i uruchomienia; opcjonalna reputacja")
    events = []
    history_sources = []
    paths = dict.fromkeys(path.expanduser().resolve() for path in (*settings.connection_logs, *settings.execution_logs))
    for log_path in paths:
        try:
            parsed = read_history_log(log_path)
            events.extend(parsed)
            history_sources.append(source_summary(str(log_path), parsed))
        except InputFileError as error:
            warnings.append(str(error))
            history_sources.append(HistorySource(str(log_path), "unavailable", 0, detail=str(error)))
    if settings.system_history:
        system_events, system_sources = collect_system_history(settings.history_hours, settings.history_max_events)
        events.extend(system_events)
        history_sources.extend(system_sources)
    for item in history_sources:
        if item.status != "read" or item.detail:
            warnings.append(f"Historia {item.name}: {item.status}. {item.detail}")
    execution_count = sum(item.execution_event_count > 0 for item in history_sources)
    execution_check = assess_execution(source, tuple(events), execution_count, settings.original_script_path)
    process_keys = {item.process_key for item in execution_check.matches if item.process_key}
    records = tuple(
        ConnectionRecord(event.timestamp, item.value, event.log_source, event.raw,
                         event.event_type, event.process_key)
        for event in events for item in extract_iocs(event.address, "history")
    )
    checked_log_count = sum(item.network_event_count > 0 for item in history_sources)
    connection_matches = tuple(
        replace(match, script_related=bool(match.process_key and match.process_key in process_keys))
        for match in correlate_iocs(iocs, records)
    )
    connection_checks = assess_connections(iocs, connection_matches, checked_log_count)

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

    announce(6, "Budowanie koncowego wyniku analizy")
    completed = get_timestamp(settings.ntp_server, settings.request_timeout)
    if settings.ntp_server and not completed.synchronized and not any("NTP" in item for item in warnings):
        warnings.append("Synchronizacja NTP nie powiodla sie; uzyto zegara systemowego")
    return AnalysisResult(
        schema_version="1.3",
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
        connection_checks=connection_checks,
        connection_matches=connection_matches,
        reputation=reputation,
        warnings=tuple(warnings),
        deobfuscated_text=transformed_text if transformations else None,
        execution_check=execution_check,
        history_sources=tuple(history_sources),
        engine_runs=engine_runs,
    )


def analyze_and_write(
    path: Path | str,
    config: AnalysisConfig | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> tuple[AnalysisResult, tuple[Path, ...]]:
    """Analizuje plik i zapisuje wersjonowane artefakty w skonfigurowanym katalogu."""

    settings = config or AnalysisConfig()
    result = analyze_file(path, settings, progress)
    outputs = write_reports(result, settings.output_dir, settings.report_formats)
    return result, outputs
