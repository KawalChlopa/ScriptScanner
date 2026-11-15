"""Odczyt dostarczonych logow i korelacja z wykrytymi IOC."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from ioc import extract_iocs
from history import read_history_log
from models import ConnectionCheck, ConnectionMatch, ConnectionRecord, IOC

TIMESTAMP_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)


def extract_timestamp(line: str) -> str | None:
    """Wyodrebnia typowy znacznik ISO 8601 z wiersza logu."""

    match = TIMESTAMP_RE.search(line)
    return match.group(1) if match else None


def parse_connection_log(
    path: Path | str,
    max_bytes: int = 10_000_000,
    max_lines: int = 100_000,
) -> tuple[ConnectionRecord, ...]:
    """Czyta tekstowy/CSV/JSONL log jako dane i wydobywa z niego adresy."""

    return tuple(
        ConnectionRecord(event.timestamp, item.value, event.log_source, event.raw,
                         event.event_type, event.process_key)
        for event in read_history_log(path, max_bytes, max_lines)
        for item in extract_iocs(event.address, "connection-log")
    )


def correlate_iocs(
    iocs: tuple[IOC, ...],
    records: tuple[ConnectionRecord, ...],
) -> tuple[ConnectionMatch, ...]:
    """Laczy IOC z historycznymi rekordami przez dokladna wartosc po normalizacji."""

    lookup = {(item.kind, item.value) for item in iocs}
    matches: list[ConnectionMatch] = []
    seen: set[tuple] = set()
    for record in records:
        candidates = [item for item in lookup if item[1] == record.address or
                      (item[0] == "url" and urlsplit(item[1]).hostname == record.address)]
        for kind, value in candidates:
            event_type = record.event_type
            if kind == "url" and value != record.address:
                event_type = f"host-{event_type}"
            key = (kind, value, record.timestamp, record.log_source, record.raw, event_type, record.process_key)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                ConnectionMatch(
                    ioc_kind=kind,
                    ioc_value=value,
                    timestamp=record.timestamp,
                    log_source=record.log_source,
                    raw=record.raw,
                    event_type=event_type,
                    process_key=record.process_key,
                )
            )
    return tuple(
        sorted(
            matches,
            key=lambda item: (item.ioc_value, item.timestamp or "", item.log_source),
        )
    )


def assess_connections(
    iocs: tuple[IOC, ...],
    matches: tuple[ConnectionMatch, ...],
    checked_log_count: int,
) -> tuple[ConnectionCheck, ...]:
    """Okresla, czy kazdy IOC znaleziono w poprawnie odczytanych logach."""

    if checked_log_count < 0:
        raise ValueError("Liczba sprawdzonych logow nie moze byc ujemna")
    grouped: dict[tuple[str, str], list[ConnectionMatch]] = {}
    for match in matches:
        key = (match.ioc_kind, match.ioc_value)
        grouped.setdefault(key, []).append(match)

    checks: list[ConnectionCheck] = []
    for ioc in iocs:
        evidence = grouped.get((ioc.kind, ioc.value), [])
        types = tuple(sorted({match.event_type for match in evidence}))
        count = len(evidence)
        if "connected" in types:
            status = "confirmed"
        elif "url-request" in types:
            status = "request-observed"
        elif "blocked" in types:
            status = "blocked"
        elif "allowed" in types:
            status = "allowed"
        elif "dns-query" in types:
            status = "dns-only"
        elif any(kind.startswith("host-") for kind in types):
            status = "host-only"
        elif count:
            status = "mentioned-only"
        elif checked_log_count:
            status = "not-observed"
        else:
            status = "not-checked"
        checks.append(
            ConnectionCheck(
                ioc_kind=ioc.kind,
                ioc_value=ioc.value,
                status=status,
                match_count=count,
                checked_log_count=checked_log_count,
                evidence_types=types,
            )
        )
    return tuple(checks)
