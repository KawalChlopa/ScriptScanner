"""Ekstrakcja i scalanie sieciowych wskaznikow kompromitacji (IOC)."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from models import IOC
from sanitization import restore_defanged_text

URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`]+", re.IGNORECASE)
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
DOMAIN_RE = re.compile(
    r"(?<![@\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)
NON_DOMAIN_SUFFIXES = frozenset({"bash", "cjs", "html", "js", "json", "log", "mjs", "ps1", "py", "sh", "txt"})


def normalize_ioc(kind: str, value: str) -> str:
    """Normalizuje IOC do stabilnej postaci porownawczej."""

    cleaned = value.rstrip(".,;:!?)]}>")
    if kind == "ip":
        return str(ipaddress.ip_address(cleaned))
    if kind == "domain":
        return cleaned.rstrip(".").lower()
    if kind == "url":
        parts = urlsplit(cleaned)
        host = (parts.hostname or "").lower()
        if not host or parts.scheme.lower() not in {"http", "https"}:
            raise ValueError("Nieprawidlowy URL")
        port = f":{parts.port}" if parts.port else ""
        netloc = host + port
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "", parts.query, ""))
    raise ValueError(f"Nieznany typ IOC: {kind}")


def extract_iocs(text: str, source: str) -> tuple[IOC, ...]:
    """Wyodrebnia URL, IPv4 i domeny z jednej reprezentacji tekstu."""

    text = restore_defanged_text(text)
    values: dict[tuple[str, str], set[str]] = {}
    occupied_domains: set[str] = set()
    for match in URL_RE.finditer(text):
        try:
            value = normalize_ioc("url", match.group(0))
        except (ValueError, ipaddress.AddressValueError):
            continue
        values.setdefault(("url", value), set()).add(source)
        host = urlsplit(value).hostname
        if host:
            occupied_domains.add(host.lower())
    for match in IP_RE.finditer(text):
        try:
            value = normalize_ioc("ip", match.group(0))
        except ValueError:
            continue
        values.setdefault(("ip", value), set()).add(source)
    for match in DOMAIN_RE.finditer(text):
        value = normalize_ioc("domain", match.group(0))
        if value in occupied_domains:
            continue
        if value.rsplit(".", 1)[-1] in NON_DOMAIN_SUFFIXES:
            continue
        # Typowe wywolanie metody, np. console.log(...), nie jest domena.
        if text[match.end() :].lstrip().startswith("("):
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            values.setdefault(("domain", value), set()).add(source)
    return tuple(
        IOC(kind, value, tuple(sorted(sources)))
        for (kind, value), sources in sorted(values.items())
    )


def merge_iocs(*groups: tuple[IOC, ...]) -> tuple[IOC, ...]:
    """Scala duplikaty IOC, zachowujac informacje o reprezentacji zrodlowej."""

    merged: dict[tuple[str, str], set[str]] = {}
    for group in groups:
        for item in group:
            merged.setdefault((item.kind, item.value), set()).update(item.sources)
    return tuple(
        IOC(kind, value, tuple(sorted(sources)))
        for (kind, value), sources in sorted(merged.items())
    )
