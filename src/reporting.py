"""Raport terminalowy oraz deterministyczne JSON i PDF bez zaleznosci runtime."""

from __future__ import annotations

import json
import os
import re
import tempfile
import textwrap
import unicodedata
from pathlib import Path
from typing import Any

from errors import ReportError
from models import AnalysisResult, to_primitive
from sanitization import defang_data, defang_observable, defang_text


def safe_component(value: str) -> str:
    """Ogranicza nazwe elementu sciezki do przenosnego, bezpiecznego podzbioru."""

    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", normalized).strip(".-")
    return cleaned[:80] or "analysis"


def report_payload(result: AnalysisResult) -> dict[str, Any]:
    """Dodaje podsumowanie do pelnego, serializowalnego wyniku analizy."""

    payload = to_primitive(result)
    for item in payload["iocs"]:
        item["value"] = defang_observable(item["kind"], item["value"])
    for item in payload["connection_matches"]:
        item["ioc_value"] = defang_observable(item["ioc_kind"], item["ioc_value"])
    payload = defang_data(payload)
    payload["summary"] = {
        "finding_count": len(result.findings),
        "high_or_critical_count": sum(
            finding.severity in {"high", "critical"} for finding in result.findings
        ),
        "obfuscation_signal_count": len(result.obfuscation_signals),
        "ioc_count": len(result.iocs),
        "connection_match_count": len(result.connection_matches),
    }
    return payload


def render_json(result: AnalysisResult) -> bytes:
    """Serializuje raport JSON w stabilnym kodowaniu UTF-8."""

    return (json.dumps(report_payload(result), ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def terminal_text(value: str, limit: int = 500) -> str:
    """Usuwa znaki sterujace, aby niezaufany tekst nie sterowal terminalem."""

    value = defang_text(value)
    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())[:limit]


def render_terminal(result: AnalysisResult) -> str:
    """Buduje szczegolowy, czytelny raport przeznaczony do terminala."""

    lines = [
        "=" * 78,
        "Analiza zakonczona - raport pasywnej analizy",
        "=" * 78,
        f"Plik:       {terminal_text(result.source.path)}",
        f"Jezyk:      {terminal_text(result.language)}",
        f"Rozmiar:    {result.source.size_bytes} B",
        f"SHA-256:    {result.hashes.sha256}",
        f"Start UTC:  {result.started_at.iso_utc} ({result.started_at.source})",
        f"Koniec UTC: {result.completed_at.iso_utc} ({result.completed_at.source})",
        "",
        "ETAPY ANALIZY",
        "  [1/6] Odczytano plik jako niezaufane dane; kodu nie uruchomiono.",
        "  [2/6] Rozpoznano jezyk i obliczono SHA-256, SHA-1 oraz MD5.",
        "  [3/6] Zastosowano reguly podejrzanych konstrukcji.",
        "  [4/6] Sprawdzono obfuskacje i pasywnie przetworzono kopie tekstu.",
        "  [5/6] Wyodrebniono IOC i porownano je z podanymi logami.",
        "  [6/6] Zbudowano wynik bez modyfikowania pliku zrodlowego.",
        "",
        f"DETEKCJE ({len(result.findings)})",
    ]
    if result.findings:
        for finding in result.findings:
            lines.append(
                f"  [{finding.severity.upper()}] {finding.rule_id}, linia {finding.line}: "
                f"{terminal_text(finding.title)}"
            )
            lines.append(f"    Dowod: {terminal_text(finding.excerpt)}")
    else:
        lines.append("  Brak")

    lines.extend(("", f"OBFUSKACJA ({len(result.obfuscation_signals)})"))
    if result.obfuscation_signals:
        for signal in result.obfuscation_signals:
            lines.append(
                f"  [{terminal_text(signal.confidence)}] {terminal_text(signal.kind)}, "
                f"linia {signal.line}: {terminal_text(signal.detail)}"
            )
    else:
        lines.append("  Brak")

    lines.extend(("", f"TRANSFORMACJE ({len(result.transformations)})"))
    if result.transformations:
        escaped_by_line: dict[int, int] = {}
        for transformation in result.transformations:
            if transformation.kind == "escaped-character":
                escaped_by_line[transformation.line] = escaped_by_line.get(transformation.line, 0) + 1
                continue
            original = terminal_text(transformation.original, 80)
            transformed = terminal_text(transformation.transformed, 120)
            lines.append(
                f"  linia {transformation.line}, {terminal_text(transformation.kind)}: "
                f"{original!r} -> {transformed!r}"
            )
        for line, count in sorted(escaped_by_line.items()):
            lines.append(f"  linia {line}, escaped-character: wykonano {count} prostych zamian")
    else:
        lines.append("  Brak")

    lines.extend(("", f"IOC ({len(result.iocs)})"))
    if result.iocs:
        for item in result.iocs:
            sources = ", ".join(terminal_text(source) for source in item.sources)
            lines.append(
                f"  {terminal_text(item.kind)}: "
                f"{terminal_text(defang_observable(item.kind, item.value))} [zrodla: {sources}]"
            )
    else:
        lines.append("  Brak")

    lines.extend(("", f"KORELACJE Z LOGAMI ({len(result.connection_matches)})"))
    if result.connection_matches:
        for match in result.connection_matches:
            lines.append(
                f"  {terminal_text(defang_observable(match.ioc_kind, match.ioc_value))} @ "
                f"{terminal_text(match.timestamp or 'brak czasu')}"
            )
            lines.append(f"    Log: {terminal_text(match.log_source)}")
    else:
        lines.append("  Brak")

    lines.extend(("", "OSTRZEZENIA"))
    lines.extend(f"  {terminal_text(warning)}" for warning in result.warnings)
    if not result.warnings:
        lines.append("  Brak")
    lines.extend(("", "Analizowany kod nie zostal uruchomiony.", "=" * 78))
    return "\n".join(lines) + "\n"


def pdf_text(value: str) -> str:
    """Transliteruje i escapuje tekst dla wbudowanej czcionki PDF Helvetica."""

    value = defang_text(value)
    ascii_text = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    return ascii_text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def pdf_lines(result: AnalysisResult) -> list[str]:
    """Buduje czytelna, liniowa reprezentacje wyniku dla raportu PDF."""

    lines = [
        "RAPORT PASYWNEJ ANALIZY SKRYPTU",
        f"Plik: {result.source.name}",
        f"Jezyk: {result.language}",
        f"SHA-256: {result.hashes.sha256}",
        f"SHA-1: {result.hashes.sha1}",
        f"MD5: {result.hashes.md5}",
        f"Start UTC: {result.started_at.iso_utc}",
        f"Koniec UTC: {result.completed_at.iso_utc}",
        "",
        f"DETEKCJE ({len(result.findings)})",
    ]
    for finding in result.findings:
        lines.append(
            f"[{finding.severity.upper()}] {finding.rule_id}, linia {finding.line}: "
            f"{finding.title} - {finding.excerpt}"
        )
    lines.extend(("", f"OBFUSKACJA ({len(result.obfuscation_signals)})"))
    for signal in result.obfuscation_signals:
        lines.append(f"[{signal.confidence}] {signal.kind}, linia {signal.line}: {signal.detail}")
    lines.extend(("", f"IOC ({len(result.iocs)})"))
    for item in result.iocs:
        value = defang_observable(item.kind, item.value)
        lines.append(f"{item.kind}: {value} (zrodla: {', '.join(item.sources)})")
    lines.extend(("", f"KORELACJE ({len(result.connection_matches)})"))
    for match in result.connection_matches:
        value = defang_observable(match.ioc_kind, match.ioc_value)
        lines.append(f"{value} @ {match.timestamp or 'brak czasu'} w {match.log_source}")
    lines.extend(("", "OSTRZEZENIA"))
    lines.extend(result.warnings or ("Brak",))
    lines.extend(("", "Analizowany kod nie zostal uruchomiony."))
    wrapped: list[str] = []
    for line in lines:
        wrapped.extend(textwrap.wrap(line, width=92, replace_whitespace=False) or [""])
    return wrapped


def build_pdf(lines: list[str]) -> bytes:
    """Tworzy minimalny, wielostronicowy PDF 1.4 z listy wierszy."""

    pages = [lines[index : index + 55] for index in range(0, len(lines), 55)] or [[]]
    font_id = 3 + 2 * len(pages)
    objects: list[bytes] = [b"", b""]
    page_ids = [3 + 2 * index for index in range(len(pages))]
    for index, page_lines in enumerate(pages):
        page_id = page_ids[index]
        content_id = page_id + 1
        commands = ["BT", "/F1 9 Tf", "48 794 Td", "12 TL"]
        commands.extend(f"({pdf_text(line)}) Tj T*" for line in page_lines)
        commands.append("ET")
        stream = "\n".join(commands).encode("ascii")
        page_object = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
        content_object = b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream"
        objects.extend((page_object, content_object))
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("ascii")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    document = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_id, body in enumerate(objects, start=1):
        offsets.append(len(document))
        document.extend(f"{object_id} 0 obj\n".encode("ascii"))
        document.extend(body)
        document.extend(b"\nendobj\n")
    xref_offset = len(document)
    document.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    document.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        document.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    document.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(document)


def render_pdf(result: AnalysisResult) -> bytes:
    """Renderuje wynik jako samowystarczalny dokument PDF."""

    return build_pdf(pdf_lines(result))


def atomic_write(path: Path, content: bytes) -> Path:
    """Zapisuje plik przez tymczasowy plik w tym samym katalogu i podmiane."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
    except OSError as error:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)
        raise ReportError(f"Nie mozna zapisac raportu {path}: {error}") from error
    return path


def analysis_directory(result: AnalysisResult, output_root: Path) -> Path:
    """Wyznacza czytelny katalog analizy na podstawie pliku, czasu i skrotu."""

    source = safe_component(Path(result.source.name).stem)
    language = safe_component(result.language)
    iso_timestamp = result.completed_at.iso_utc
    if "." in iso_timestamp:
        timestamp_base, fraction = iso_timestamp.split(".", 1)
        iso_timestamp = f"{timestamp_base}-{fraction.rstrip('Z')[:3]}Z"
    timestamp = iso_timestamp.replace("T", "_").replace(":", "-")
    timestamp = timestamp.replace(".", "-").replace("Z", "_UTC")
    readable_name = (
        f"{source}-{language}__{safe_component(timestamp)}__sha256-{result.hashes.sha256[:8]}"
    )
    return Path(output_root).resolve() / readable_name


def write_reports(
    result: AnalysisResult,
    output_root: Path,
    formats: tuple[str, ...],
) -> tuple[Path, ...]:
    """Zapisuje wybrane raporty i kopie danych pochodnych, nie ruszajac zrodla."""

    directory = analysis_directory(result, output_root)
    renderers = {"json": render_json, "pdf": render_pdf}
    written: list[Path] = []
    for report_format in formats:
        renderer = renderers.get(report_format)
        if renderer is None:
            raise ReportError(f"Nieobslugiwany format raportu: {report_format}")
        written.append(atomic_write(directory / f"report.{report_format}", renderer(result)))
    if result.deobfuscated_text is not None:
        written.append(
            atomic_write(
                directory / "deobfuscated.txt",
                defang_text(result.deobfuscated_text).encode("utf-8"),
            )
        )
    return tuple(written)
