"""Monitor aktualnych polaczen TCP/UDP na Windowsie i Linuksie."""

from __future__ import annotations

import argparse
import importlib
import json
import platform
import socket
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from errors import AnalysisError, ConfigurationError, MonitorError
from models import LiveConnection, to_primitive
from reporting import atomic_write, safe_component, terminal_text
from sanitization import defang_data, defang_observable

MAX_DURATION_SECONDS = 86_400.0
MAX_INTERVAL_SECONDS = 60.0
MAX_EVENTS = 100_000


@dataclass(frozen=True, slots=True)
class MonitorConfig:
    """Walidowana konfiguracja probkowania polaczen systemowych."""

    duration: float = 30.0
    interval: float = 1.0
    include_unconnected: bool = False
    max_events: int = MAX_EVENTS

    def __post_init__(self) -> None:
        if not 0 <= self.duration <= MAX_DURATION_SECONDS:
            raise ConfigurationError(
                f"Czas monitorowania musi byc w zakresie 0-{MAX_DURATION_SECONDS:g} sekund"
            )
        if not 0.1 <= self.interval <= MAX_INTERVAL_SECONDS:
            raise ConfigurationError(
                f"Interwal musi byc w zakresie 0.1-{MAX_INTERVAL_SECONDS:g} sekund"
            )
        if not 1 <= self.max_events <= MAX_EVENTS:
            raise ConfigurationError(f"Limit zdarzen musi byc w zakresie 1-{MAX_EVENTS}")


def utc_now() -> str:
    """Zwraca biezacy czas UTC w stabilnym formacie ISO 8601."""

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def load_psutil() -> Any:
    """Laduje warstwe systemowa z czytelnym bledem instalacji."""

    try:
        return importlib.import_module("psutil")
    except ImportError as error:
        raise MonitorError(
            "Brak biblioteki psutil. Zainstaluj projekt ponownie: "
            "python -m pip install ."
        ) from error


def endpoint_parts(endpoint: Any) -> tuple[str | None, int | None]:
    """Normalizuje punkt koncowy psutil do adresu i portu."""

    if not endpoint:
        return None, None
    address = getattr(endpoint, "ip", None)
    port = getattr(endpoint, "port", None)
    if address is None and isinstance(endpoint, (tuple, list)) and len(endpoint) >= 2:
        address, port = endpoint[0], endpoint[1]
    if address is None or port is None:
        return None, None
    try:
        return str(address), int(port)
    except (TypeError, ValueError):
        return None, None


def process_identity(pid: int | None, backend: Any) -> tuple[str | None, str | None]:
    """Pobiera nazwe i sciezke procesu, tolerujac brak uprawnien i zakonczenie procesu."""

    if pid is None:
        return None, None
    expected_errors = tuple(
        error_type
        for error_type in (
            getattr(backend, "AccessDenied", None),
            getattr(backend, "NoSuchProcess", None),
            getattr(backend, "ZombieProcess", None),
        )
        if isinstance(error_type, type) and issubclass(error_type, BaseException)
    )
    try:
        process = backend.Process(pid)
    except expected_errors:
        return None, None

    try:
        name = process.name() or None
    except expected_errors:
        name = None
    try:
        executable = process.exe() or None
    except expected_errors:
        executable = None
    return name, executable


def normalize_connection(raw: Any, backend: Any, observed_at_utc: str) -> LiveConnection | None:
    """Mapuje rekord psutil na stabilny, serializowalny model projektu."""

    family = {socket.AF_INET: "ipv4", socket.AF_INET6: "ipv6"}.get(raw.family)
    protocol = {socket.SOCK_STREAM: "tcp", socket.SOCK_DGRAM: "udp"}.get(raw.type)
    local_address, local_port = endpoint_parts(raw.laddr)
    remote_address, remote_port = endpoint_parts(raw.raddr)
    if family is None or protocol is None or local_address is None or local_port is None:
        return None
    pid = raw.pid if isinstance(raw.pid, int) and raw.pid >= 0 else None
    process_name, process_executable = process_identity(pid, backend)
    status = str(raw.status or "NONE")
    return LiveConnection(
        observed_at_utc=observed_at_utc,
        system=platform.system().lower() or "unknown",
        protocol=protocol,
        family=family,
        status=status,
        local_address=local_address,
        local_port=local_port,
        remote_address=remote_address,
        remote_port=remote_port,
        pid=pid,
        process_name=process_name,
        process_executable=process_executable,
    )


def connection_key(connection: LiveConnection) -> tuple[Any, ...]:
    """Buduje klucz jednego wcielenia polaczenia do detekcji nowych zdarzen."""

    return (
        connection.protocol,
        connection.family,
        connection.local_address,
        connection.local_port,
        connection.remote_address,
        connection.remote_port,
        connection.pid,
    )


def collect_connections(
    backend: Any | None = None,
    *,
    include_unconnected: bool = False,
    observed_at_utc: str | None = None,
) -> tuple[LiveConnection, ...]:
    """Pobiera jedna migawke systemowych polaczen internetowych."""

    provider = backend or load_psutil()
    expected_errors = tuple(
        error_type
        for error_type in (getattr(provider, "AccessDenied", None), OSError, RuntimeError)
        if isinstance(error_type, type) and issubclass(error_type, BaseException)
    )
    try:
        raw_connections = provider.net_connections(kind="inet")
    except expected_errors as error:
        raise MonitorError(
            "System odmowil odczytu polaczen. Uruchom terminal jako administrator/root."
        ) from error

    observed = observed_at_utc or utc_now()
    normalized: list[LiveConnection] = []
    seen: set[tuple[Any, ...]] = set()
    for raw in raw_connections:
        connection = normalize_connection(raw, provider, observed)
        if connection is None:
            continue
        if not include_unconnected and connection.remote_address is None:
            continue
        key = connection_key(connection)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(connection)
    return tuple(sorted(normalized, key=connection_key))


def monitor_connections(
    config: MonitorConfig,
    *,
    backend: Any | None = None,
    emit: Callable[[LiveConnection], None] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    timestamp_factory: Callable[[], str] = utc_now,
) -> tuple[LiveConnection, ...]:
    """Probkuje system i zwraca polaczenia nowe wzgledem poprzedniej migawki."""

    provider = backend or load_psutil()
    started = monotonic()
    previous_keys: set[tuple[Any, ...]] = set()
    events: list[LiveConnection] = []
    while True:
        snapshot = collect_connections(
            provider,
            include_unconnected=config.include_unconnected,
            observed_at_utc=timestamp_factory(),
        )
        current_keys = {connection_key(item) for item in snapshot}
        for connection in snapshot:
            if connection_key(connection) in previous_keys:
                continue
            if len(events) >= config.max_events:
                raise MonitorError(f"Monitor osiagnal limit {config.max_events} zdarzen")
            events.append(connection)
            if emit is not None:
                emit(connection)
        previous_keys = current_keys

        elapsed = monotonic() - started
        if config.duration == 0 or elapsed >= config.duration:
            break
        sleeper(min(config.interval, config.duration - elapsed))
    return tuple(events)


def render_connection_event(connection: LiveConnection) -> str:
    """Buduje bezpieczny, pojedynczy wiersz zdarzenia dla terminala."""

    remote = "brak"
    if connection.remote_address is not None:
        remote_address = defang_observable("ip", connection.remote_address)
        remote = f"{remote_address}:{connection.remote_port}"
    process = connection.process_name or "nieznany proces"
    pid = str(connection.pid) if connection.pid is not None else "?"
    return terminal_text(
        f"[{connection.observed_at_utc}] {connection.protocol.upper()} "
        f"{defang_observable('ip', connection.local_address)}:{connection.local_port} -> {remote} "
        f"PID={pid} {process} ({connection.status})",
        1000,
    )


def render_jsonl(events: tuple[LiveConnection, ...]) -> bytes:
    """Serializuje zdarzenia jako JSON Lines zgodny z parserem logow projektu."""

    lines: list[str] = []
    for event in events:
        payload = to_primitive(event)
        payload["local_address"] = defang_observable("ip", payload["local_address"])
        if payload["remote_address"] is not None:
            payload["remote_address"] = defang_observable("ip", payload["remote_address"])
        lines.append(json.dumps(defang_data(payload), ensure_ascii=False))
    return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")


def monitor_directory(output_root: Path, started_at_utc: str, system_name: str) -> Path:
    """Wyznacza czytelny, przenosny katalog jednej sesji monitorowania."""

    timestamp = started_at_utc.replace("T", "_").replace(":", "-")
    timestamp = timestamp.replace(".", "-").replace("Z", "_UTC")
    name = f"system-connections__{safe_component(timestamp)}__{safe_component(system_name)}"
    return output_root.expanduser().resolve() / name


def write_monitor_report(
    events: tuple[LiveConnection, ...],
    output_root: Path,
    started_at_utc: str,
) -> Path:
    """Zapisuje log JSONL atomowo w katalogu sesji monitorowania."""

    system_name = platform.system().lower() or "unknown"
    directory = monitor_directory(output_root, started_at_utc, system_name)
    return atomic_write(directory / "connections.jsonl", render_jsonl(events))


def build_parser() -> argparse.ArgumentParser:
    """Buduje parser osobnego CLI monitora polaczen."""

    parser = argparse.ArgumentParser(
        prog="infa-sled-monitor",
        description="Monitor aktualnych polaczen TCP/UDP na Windowsie i Linuksie",
    )
    parser.add_argument("--duration", type=float, default=30.0, help="czas pracy w sekundach")
    parser.add_argument("--interval", type=float, default=1.0, help="odstep probkowania")
    parser.add_argument("--max-events", type=int, default=MAX_EVENTS)
    parser.add_argument(
        "--include-unconnected",
        action="store_true",
        help="uwzglednij porty nasluchujace i gniazda UDP bez zdalnego adresu",
    )
    parser.add_argument("-o", "--output", type=Path, default=Path("report"))
    parser.add_argument(
        "--mode",
        choices=("files", "terminal", "both"),
        default="both",
        help="files: zapis JSONL, terminal: podglad, both: oba wyjscia",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Uruchamia monitor i zwraca przewidywalny kod zakonczenia."""

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        config = MonitorConfig(
            duration=args.duration,
            interval=args.interval,
            include_unconnected=args.include_unconnected,
            max_events=args.max_events,
        )
        started_at = utc_now()
        if args.mode in {"terminal", "both"}:
            print(
                f"Monitorowanie polaczen przez {config.duration:g} s "
                f"(interwal {config.interval:g} s)..."
            )
            emitter: Callable[[LiveConnection], None] | None = (
                lambda event: print(render_connection_event(event))
            )
        else:
            emitter = None
        events = monitor_connections(config, emit=emitter)
        output = None
        if args.mode in {"files", "both"}:
            output = write_monitor_report(events, args.output, started_at)
    except (AnalysisError, ConfigurationError) as error:
        print(f"Blad: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nMonitorowanie przerwane przez uzytkownika.", file=sys.stderr)
        return 130

    print(f"Monitorowanie zakonczone: {len(events)} nowych polaczen.")
    if output is not None:
        print(f"Zapisany log: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
