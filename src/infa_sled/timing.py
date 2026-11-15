"""Znaczniki czasu systemowego i opcjonalna, jawna synchronizacja NTP."""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable
from datetime import datetime, timezone

from .models import TimestampInfo

NTP_EPOCH_DELTA = 2_208_988_800


def format_utc(value: datetime) -> str:
    """Normalizuje date do ISO 8601 w UTC z sufiksem Z."""

    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def system_timestamp(now: datetime | None = None, source: str = "system") -> TimestampInfo:
    """Buduje znacznik z lokalnego zegara systemowego."""

    value = now or datetime.now(timezone.utc)
    return TimestampInfo(iso_utc=format_utc(value), source=source, synchronized=False)


def query_ntp(
    server: str,
    timeout: float = 5.0,
    socket_factory: Callable[..., socket.socket] = socket.socket,
) -> TimestampInfo:
    """Pobiera czas NTP po UDP; funkcja jest wywolywana tylko po jawnej zgodzie."""

    if not server or timeout <= 0:
        raise ValueError("Serwer NTP i dodatni limit czasu sa wymagane")
    request = b"\x1b" + 47 * b"\0"
    client = socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        client.settimeout(timeout)
        client.sendto(request, (server, 123))
        response, _ = client.recvfrom(512)
    finally:
        client.close()
    if len(response) < 48:
        raise OSError("Odpowiedz NTP jest za krotka")
    seconds, fraction = struct.unpack("!II", response[40:48])
    unix_seconds = seconds - NTP_EPOCH_DELTA + fraction / 2**32
    value = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    return TimestampInfo(
        iso_utc=format_utc(value),
        source="ntp",
        ntp_server=server,
        synchronized=True,
    )


def get_timestamp(
    ntp_server: str | None = None,
    timeout: float = 5.0,
    ntp_query: Callable[[str, float], TimestampInfo] = query_ntp,
) -> TimestampInfo:
    """Uzywa NTP na zadanie, a przy awarii jawnie oznacza bezpieczny fallback."""

    if not ntp_server:
        return system_timestamp()
    try:
        return ntp_query(ntp_server, timeout)
    except (OSError, TimeoutError, ValueError, socket.gaierror):
        fallback = system_timestamp(source="system-fallback")
        return TimestampInfo(
            iso_utc=fallback.iso_utc,
            source=fallback.source,
            ntp_server=ntp_server,
            synchronized=False,
        )
