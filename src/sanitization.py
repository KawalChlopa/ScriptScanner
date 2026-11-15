"""Rozbrajanie obserwabli sieciowych przed prezentacja i zapisem raportu."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
IPV6_RE = re.compile(r"(?<![\w:])(?=[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{3,}(?![\w:])")


def defang_ip(value: str) -> str:
    """Rozbraja poprawny IPv4 lub IPv6, pozostawiajac inne napisy bez zmian."""

    cleaned = value.strip()
    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError:
        return value
    normalized = str(address)
    if address.version == 4:
        return normalized.replace(".", "[.]")
    return normalized.replace(":", "[:]")


def defang_url(value: str) -> str:
    """Rozbraja schemat i czesc adresowa URL bez zmiany sciezki i zapytania."""

    scheme, separator, remainder = value.partition("://")
    if not separator or scheme.lower() not in {"http", "https"}:
        return value
    boundary = len(remainder)
    for marker in "/?#":
        position = remainder.find(marker)
        if position >= 0:
            boundary = min(boundary, position)
    authority = remainder[:boundary]
    suffix = remainder[boundary:]
    userinfo, at, host_port = authority.rpartition("@")
    prefix = f"{userinfo}@" if at else ""

    if host_port.startswith("[") and "]" in host_port:
        host, closing, port = host_port[1:].partition("]")
        safe_host_port = f"[{defang_ip(host)}]{port if closing else ''}"
    else:
        host, colon, port = host_port.rpartition(":")
        if not colon or not port.isdigit():
            host, colon, port = host_port, "", ""
        safe_host = defang_ip(host)
        if safe_host == host:
            safe_host = host.replace(".", "[.]")
        safe_host_port = safe_host + (f":{port}" if colon else "")
    safe_scheme = "hxxps" if scheme.lower() == "https" else "hxxp"
    return f"{safe_scheme}://{prefix}{safe_host_port}{suffix}"


def defang_text(value: str) -> str:
    """Rozbraja wszystkie aktywne URL oraz poprawne adresy IP w tekscie."""

    def replace_url(match: re.Match[str]) -> str:
        return defang_url(match.group(0))

    def replace_ip(match: re.Match[str]) -> str:
        return defang_ip(match.group(0))

    defanged = URL_RE.sub(replace_url, value)
    defanged = IPV4_RE.sub(replace_ip, defanged)
    return IPV6_RE.sub(replace_ip, defanged)


def defang_observable(kind: str, value: str) -> str:
    """Rozbraja IOC zgodnie z jego typem, lacznie z samodzielna domena."""

    if kind == "ip":
        return defang_ip(value)
    if kind == "domain":
        return value.replace(".", "[.]")
    return defang_text(value)


def defang_data(value: Any) -> Any:
    """Rekurencyjnie rozbraja URL i IP w strukturze przeznaczonej do raportu."""

    if isinstance(value, str):
        return defang_text(value)
    if isinstance(value, dict):
        return {key: defang_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [defang_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(defang_data(item) for item in value)
    return value


def restore_defanged_text(value: str) -> str:
    """Normalizuje popularne znaczniki defangowania tylko na potrzeby korelacji."""

    restored = re.sub(r"\bhxxps://", "https://", value, flags=re.IGNORECASE)
    restored = re.sub(r"\bhxxp://", "http://", restored, flags=re.IGNORECASE)
    return restored.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
