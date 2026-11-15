"""Detekcja i ograniczona, pasywna defuskacja literałów."""

from __future__ import annotations

import base64
import binascii
import re

from .models import ObfuscationSignal, Transformation
from .rules import line_number

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])")
HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
CONCAT_RE = re.compile(
    r"(?P<quote>['\"])(?P<left>[^'\"\r\n]{0,200})(?P=quote)\s*\+\s*"
    r"(?P=quote)(?P<right>[^'\"\r\n]{0,200})(?P=quote)"
)


def printable_ratio(text: str) -> float:
    """Oblicza udzial czytelnych znakow w zdekodowanym tekscie."""

    if not text:
        return 0.0
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
    return printable / len(text)


def decode_base64_literal(candidate: str, max_decoded_bytes: int = 100_000) -> str | None:
    """Dekoduje tylko poprawny Base64 dajacy w przewadze czytelny tekst."""

    if len(candidate) > max_decoded_bytes * 2:
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded or len(decoded) > max_decoded_bytes:
        return None
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = decoded.decode(encoding)
        except UnicodeDecodeError:
            continue
        if printable_ratio(text) >= 0.85:
            return text
    return None


def detect_obfuscation(text: str) -> tuple[ObfuscationSignal, ...]:
    """Rozpoznaje wybrane wskazniki zaciemniania bez uruchamiania kodu."""

    signals: list[ObfuscationSignal] = []
    for match in BASE64_RE.finditer(text):
        if decode_base64_literal(match.group(1)) is not None:
            signals.append(
                ObfuscationSignal(
                    "base64",
                    "high",
                    line_number(text, match.start()),
                    "Czytelny tekst zakodowany jako Base64",
                )
            )
    for pattern, kind, detail in (
        (HEX_ESCAPE_RE, "hex-escapes", "Sekwencje znakow zapisane jako \\xNN"),
        (UNICODE_ESCAPE_RE, "unicode-escapes", "Sekwencje znakow zapisane jako \\uNNNN"),
    ):
        matches = list(pattern.finditer(text))
        if len(matches) >= 2:
            signals.append(
                ObfuscationSignal(
                    kind,
                    "medium",
                    line_number(text, matches[0].start()),
                    detail,
                )
            )
    _, concat_transformations = simplify_string_concatenations(text)
    if len(concat_transformations) >= 2:
        signals.append(
            ObfuscationSignal(
                "string-concatenation",
                "medium",
                concat_transformations[0].line,
                "Lancuch zlozony z wielu sasiadujacych literalow",
            )
        )
    for index, line in enumerate(text.splitlines(), start=1):
        if len(line) > 500:
            signals.append(
                ObfuscationSignal("long-line", "low", index, "Linia ma ponad 500 znakow")
            )
    return tuple(signals)


def decode_escaped_literals(text: str) -> tuple[str, tuple[Transformation, ...]]:
    """Zamienia proste zapisy \\xNN i \\uNNNN na znaki w kopii tekstu."""

    transformations: list[Transformation] = []

    def replace(match: re.Match[str]) -> str:
        transformed = chr(int(match.group(1), 16))
        transformations.append(
            Transformation(
                "escaped-character",
                line_number(text, match.start()),
                match.group(0),
                transformed,
            )
        )
        return transformed

    decoded = HEX_ESCAPE_RE.sub(replace, text)
    decoded = UNICODE_ESCAPE_RE.sub(replace, decoded)
    return decoded, tuple(transformations)


def simplify_string_concatenations(
    text: str,
    max_passes: int = 20,
) -> tuple[str, tuple[Transformation, ...]]:
    """Laczy proste literały z operatorem plus w ograniczonej liczbie przejsc."""

    current = text
    transformations: list[Transformation] = []
    for _ in range(max_passes):
        match = CONCAT_RE.search(current)
        if not match:
            break
        quote = match.group("quote")
        replacement = f"{quote}{match.group('left')}{match.group('right')}{quote}"
        transformations.append(
            Transformation(
                "string-concatenation",
                line_number(current, match.start()),
                match.group(0),
                replacement,
            )
        )
        current = current[: match.start()] + replacement + current[match.end() :]
    return current, tuple(transformations)


def deobfuscate(text: str) -> tuple[str, tuple[Transformation, ...]]:
    """Tworzy czytelniejsza reprezentacje, nigdy nie wykonujac wyniku."""

    current = text
    transformations: list[Transformation] = []
    for match in reversed(list(BASE64_RE.finditer(current))):
        decoded = decode_base64_literal(match.group(1))
        if decoded is None:
            continue
        transformations.append(
            Transformation(
                "base64",
                line_number(current, match.start()),
                match.group(1),
                decoded,
            )
        )
        current = current[: match.start(1)] + decoded + current[match.end(1) :]
    current, escaped = decode_escaped_literals(current)
    transformations.extend(escaped)
    current, concatenated = simplify_string_concatenations(current)
    transformations.extend(concatenated)
    transformations.sort(key=lambda item: (item.line, item.kind, item.original))
    return current, tuple(transformations)
