"""Bezpieczny odczyt, identyfikacja i sumy kontrolne plikow skryptowych."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .errors import InputFileError, UnsupportedLanguageError
from .models import Hashes, ScriptInput

EXTENSION_LANGUAGES = {
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".sh": "bash",
    ".bash": "bash",
}


def compute_hashes(data: bytes) -> Hashes:
    """Oblicza wymagane identyfikatory materialu bez jego modyfikacji."""

    return Hashes(
        sha256=hashlib.sha256(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),  # noqa: S324 - wymaganie identyfikacyjne
        md5=hashlib.md5(data).hexdigest(),  # noqa: S324 - wymaganie identyfikacyjne
    )


def decode_script(data: bytes) -> tuple[str, str]:
    """Dekoduje tekst, obslugujac BOM i typowe polskie pliki legacy."""

    if b"\x00" in data[:4096] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise InputFileError("Plik wyglada na binarny (wykryto bajty NUL)")
    candidates = [("utf-8-sig", "utf-8")]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        candidates.append(("utf-16", "utf-16"))
    candidates.append(("cp1250", "cp1250"))
    for codec, label in candidates:
        try:
            return data.decode(codec), label
        except (UnicodeDecodeError, UnicodeError):
            continue
    raise InputFileError("Nie udalo sie zdekodowac pliku jako tekst")


def detect_language(path: Path, text: str) -> str:
    """Rozpoznaje PowerShell, JavaScript albo Bash z rozszerzenia i tresci."""

    extension_match = EXTENSION_LANGUAGES.get(path.suffix.lower())
    if extension_match:
        return extension_match

    first_line = text.splitlines()[0].lower() if text.splitlines() else ""
    if first_line.startswith("#!"):
        if "pwsh" in first_line or "powershell" in first_line:
            return "powershell"
        if any(shell in first_line for shell in ("bash", "/sh", "zsh")):
            return "bash"
        if "node" in first_line:
            return "javascript"

    lowered = text.lower()
    scores = {
        "powershell": sum(token in lowered for token in ("$env:", "write-host", "invoke-", "param(")),
        "javascript": sum(token in lowered for token in ("const ", "let ", "function ", "require(")),
        "bash": sum(token in lowered for token in ("#!/bin/", "fi\n", "then\n", "export ", "$(")),
    }
    language, score = max(scores.items(), key=lambda item: item[1])
    if score:
        return language
    raise UnsupportedLanguageError("Nie rozpoznano PowerShell, JavaScript ani Bash")


def modified_at_utc(path: Path) -> str:
    """Zwraca czas modyfikacji pliku w jednoznacznym formacie UTC."""

    timestamp = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return timestamp.isoformat().replace("+00:00", "Z")


def read_script(path: Path | str, max_bytes: int = 5_000_000) -> ScriptInput:
    """Wczytuje niezaufany skrypt jako dane, z limitem rozmiaru i bez wykonania."""

    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise InputFileError(f"Plik nie istnieje lub nie jest zwyklym plikiem: {resolved}")
    size = resolved.stat().st_size
    if size > max_bytes:
        raise InputFileError(f"Plik przekracza limit {max_bytes} bajtow")
    try:
        with resolved.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
    except OSError as error:
        raise InputFileError(f"Nie mozna odczytac pliku: {error}") from error
    if len(raw) > max_bytes:
        raise InputFileError(f"Plik przekracza limit {max_bytes} bajtow")
    text, encoding = decode_script(raw)
    language = detect_language(resolved, text)
    return ScriptInput(
        path=resolved,
        raw=raw,
        text=text,
        encoding=encoding,
        language=language,
        hashes=compute_hashes(raw),
        modified_at_utc=modified_at_utc(resolved),
    )
