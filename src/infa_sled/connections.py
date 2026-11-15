"""Odczyt dostarczonych logow i korelacja z wykrytymi IOC."""

from __future__ import annotations

import re
from pathlib import Path

from .errors import InputFileError
from .ioc import extract_iocs
from .models import ConnectionMatch, ConnectionRecord, IOC

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

    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise InputFileError(f"Log nie istnieje: {resolved}")
    if resolved.stat().st_size > max_bytes:
        raise InputFileError(f"Log przekracza limit {max_bytes} bajtow")
    try:
        raw = resolved.read_bytes()
        text = raw.decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as error:
        raise InputFileError(f"Nie mozna odczytac logu jako UTF-8: {error}") from error
    if len(raw) > max_bytes:
        raise InputFileError(f"Log przekracza limit {max_bytes} bajtow")

    records: list[ConnectionRecord] = []
    for index, line in enumerate(text.splitlines()):
        if index >= max_lines:
            raise InputFileError(f"Log przekracza limit {max_lines} wierszy")
        timestamp = extract_timestamp(line)
        for ioc in extract_iocs(line, "connection-log"):
            records.append(
                ConnectionRecord(
                    timestamp=timestamp,
                    address=ioc.value,
                    log_source=str(resolved),
                    raw=line[:1000],
                )
            )
    return tuple(records)


def correlate_iocs(
    iocs: tuple[IOC, ...],
    records: tuple[ConnectionRecord, ...],
) -> tuple[ConnectionMatch, ...]:
    """Laczy IOC z historycznymi rekordami przez dokladna wartosc po normalizacji."""

    lookup = {(item.kind, item.value) for item in iocs}
    matches: list[ConnectionMatch] = []
    seen: set[tuple[str, str, str | None, str, str]] = set()
    for record in records:
        candidates = [item for item in lookup if item[1] == record.address]
        for kind, value in candidates:
            key = (kind, value, record.timestamp, record.log_source, record.raw)
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
                )
            )
    return tuple(
        sorted(
            matches,
            key=lambda item: (item.ioc_value, item.timestamp or "", item.log_source),
        )
    )
