"""Jawnie opcjonalne zapytania reputacyjne wysylajace wylacznie IOC."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from models import IOC, ReputationResult


def virustotal_request(ioc: IOC, api_key: str) -> Request:
    """Buduje odczytowe zapytanie VirusTotal v3 dla pojedynczego IOC."""

    if ioc.kind == "ip":
        resource = f"ip_addresses/{quote(ioc.value, safe='')}"
    elif ioc.kind == "domain":
        resource = f"domains/{quote(ioc.value, safe='')}"
    elif ioc.kind == "url":
        identifier = base64.urlsafe_b64encode(ioc.value.encode("utf-8")).decode("ascii").rstrip("=")
        resource = f"urls/{identifier}"
    else:
        raise ValueError(f"Nieobslugiwany IOC: {ioc.kind}")
    return Request(
        f"https://www.virustotal.com/api/v3/{resource}",
        headers={"accept": "application/json", "x-apikey": api_key},
        method="GET",
    )


def urlhaus_request(ioc: IOC, api_key: str) -> Request:
    """Buduje odczytowe zapytanie URLhaus dla URL albo hosta."""

    if ioc.kind == "url":
        endpoint = "url"
        field = "url"
    elif ioc.kind in {"ip", "domain"}:
        endpoint = "host"
        field = "host"
    else:
        raise ValueError(f"Nieobslugiwany IOC: {ioc.kind}")
    return Request(
        f"https://urlhaus-api.abuse.ch/v1/{endpoint}/",
        data=urlencode({field: ioc.value}).encode("ascii"),
        headers={
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Auth-Key": api_key,
        },
        method="POST",
    )


def read_json(
    request: Request,
    timeout: float,
    opener: Callable[..., Any] = urlopen,
) -> dict[str, Any]:
    """Odczytuje ograniczona odpowiedz JSON bez wykonywania zawartosci."""

    with opener(request, timeout=timeout) as response:
        payload = response.read(1_000_001)
    if len(payload) > 1_000_000:
        raise ValueError("Odpowiedz reputacyjna przekracza limit 1 MB")
    parsed = json.loads(payload.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Odpowiedz reputacyjna nie jest obiektem JSON")
    return parsed


def parse_virustotal(ioc: IOC, payload: dict[str, Any]) -> ReputationResult:
    """Mapuje odpowiedz VirusTotal do wspolnego modelu."""

    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    attributes = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}
    stats = (
        attributes.get("last_analysis_stats")
        if isinstance(attributes.get("last_analysis_stats"), dict)
        else {}
    )
    malicious = int(stats.get("malicious", 0) or 0) + int(stats.get("suspicious", 0) or 0)
    reference = data.get("links", {}).get("self") if isinstance(data.get("links"), dict) else None
    return ReputationResult(
        provider="virustotal",
        ioc_kind=ioc.kind,
        ioc_value=ioc.value,
        status="malicious" if malicious else "not-detected",
        malicious_count=malicious,
        reference=reference,
    )


def parse_urlhaus(ioc: IOC, payload: dict[str, Any]) -> ReputationResult:
    """Mapuje odpowiedz URLhaus do wspolnego modelu."""

    query_status = str(payload.get("query_status", "unknown"))
    listed = query_status == "ok"
    reference = payload.get("urlhaus_reference")
    return ReputationResult(
        provider="urlhaus",
        ioc_kind=ioc.kind,
        ioc_value=ioc.value,
        status="listed" if listed else "not-listed" if query_status == "no_results" else "unknown",
        malicious_count=1 if listed else 0 if query_status == "no_results" else None,
        reference=str(reference) if reference else None,
    )


def check_reputation(
    iocs: tuple[IOC, ...],
    provider: str,
    api_key: str,
    timeout: float = 5.0,
    opener: Callable[..., Any] = urlopen,
) -> tuple[ReputationResult, ...]:
    """Sprawdza IOC pojedynczo i zamienia awarie uslugi na wynik kontrolowany."""

    if provider not in {"virustotal", "urlhaus"}:
        raise ValueError("Nieobslugiwany dostawca reputacji")
    results: list[ReputationResult] = []
    for ioc in iocs:
        try:
            request = (
                virustotal_request(ioc, api_key)
                if provider == "virustotal"
                else urlhaus_request(ioc, api_key)
            )
            payload = read_json(request, timeout, opener)
            result = (
                parse_virustotal(ioc, payload)
                if provider == "virustotal"
                else parse_urlhaus(ioc, payload)
            )
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
            result = ReputationResult(
                provider=provider,
                ioc_kind=ioc.kind,
                ioc_value=ioc.value,
                status=f"error:{type(error).__name__}",
                malicious_count=None,
                reference=None,
            )
        results.append(result)
    return tuple(results)
