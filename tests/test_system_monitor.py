from __future__ import annotations

import json
import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from errors import ConfigurationError, MonitorError
from models import LiveConnection
from system_monitor import (
    MonitorConfig,
    build_parser,
    collect_connections,
    connection_key,
    endpoint_parts,
    load_psutil,
    main,
    monitor_connections,
    monitor_directory,
    normalize_connection,
    process_identity,
    render_connection_event,
    render_jsonl,
    utc_now,
    write_monitor_report,
)


class FakeAccessDenied(Exception):
    pass


class FakeNoSuchProcess(Exception):
    pass


class FakeZombieProcess(Exception):
    pass


class FakeProcess:
    def __init__(self, name: str = "browser.exe", executable: str = "C:/browser.exe") -> None:
        self.process_name = name
        self.executable = executable

    def name(self) -> str:
        return self.process_name

    def exe(self) -> str:
        return self.executable


def raw_connection(
    *,
    remote: tuple[str, int] | tuple[()] = ("203.0.113.10", 443),
    pid: int | None = 42,
    family: int = socket.AF_INET,
    kind: int = socket.SOCK_STREAM,
) -> SimpleNamespace:
    return SimpleNamespace(
        family=family,
        type=kind,
        laddr=("192.0.2.10", 50000),
        raddr=remote,
        status="ESTABLISHED",
        pid=pid,
    )


class FakeBackend:
    AccessDenied = FakeAccessDenied
    NoSuchProcess = FakeNoSuchProcess
    ZombieProcess = FakeZombieProcess

    def __init__(self, snapshots: list[list[SimpleNamespace]]) -> None:
        self.snapshots = snapshots
        self.index = 0
        self.kind = None

    def net_connections(self, *, kind: str) -> list[SimpleNamespace]:
        self.kind = kind
        selected = self.snapshots[min(self.index, len(self.snapshots) - 1)]
        self.index += 1
        return selected

    def Process(self, pid: int) -> FakeProcess:
        if pid == 13:
            raise FakeAccessDenied(pid)
        return FakeProcess()


def sample_event(**values: object) -> LiveConnection:
    defaults: dict[str, object] = {
        "observed_at_utc": "2026-11-15T12:00:00.000Z",
        "system": "windows",
        "protocol": "tcp",
        "family": "ipv4",
        "status": "ESTABLISHED",
        "local_address": "192.0.2.10",
        "local_port": 50000,
        "remote_address": "203.0.113.10",
        "remote_port": 443,
        "pid": 42,
        "process_name": "browser.exe",
        "process_executable": "C:/browser.exe",
    }
    defaults.update(values)
    return LiveConnection(**defaults)  # type: ignore[arg-type]


class MonitorConfigurationTests(unittest.TestCase):
    def test_config_accepts_boundaries_and_rejects_invalid_values(self) -> None:
        self.assertEqual(MonitorConfig(duration=0, interval=0.1, max_events=1).duration, 0)
        invalid = (
            {"duration": -1},
            {"duration": 86_401},
            {"interval": 0},
            {"interval": 61},
            {"max_events": 0},
            {"max_events": 100_001},
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ConfigurationError):
                MonitorConfig(**values)

    def test_utc_now_and_dependency_error_are_controlled(self) -> None:
        self.assertTrue(utc_now().endswith("Z"))
        with patch("system_monitor.importlib.import_module", side_effect=ImportError):
            with self.assertRaises(MonitorError):
                load_psutil()

    def test_parser_uses_expected_defaults_and_options(self) -> None:
        parser = build_parser()
        defaults = parser.parse_args([])
        selected = parser.parse_args(["--duration", "0", "--mode", "files"])
        self.assertEqual(defaults.output, Path("report"))
        self.assertEqual(selected.duration, 0)
        self.assertEqual(selected.mode, "files")


class MonitorCollectionTests(unittest.TestCase):
    def test_endpoint_parts_supports_tuples_and_rejects_invalid_values(self) -> None:
        endpoint = SimpleNamespace(ip="2001:db8::1", port=443)
        self.assertEqual(endpoint_parts(("203.0.113.1", "80")), ("203.0.113.1", 80))
        self.assertEqual(endpoint_parts(endpoint), ("2001:db8::1", 443))
        self.assertEqual(endpoint_parts(()), (None, None))
        self.assertEqual(endpoint_parts(("host", "bad")), (None, None))

    def test_process_identity_handles_success_missing_pid_and_access_denied(self) -> None:
        backend = FakeBackend([[]])
        self.assertEqual(process_identity(42, backend), ("browser.exe", "C:/browser.exe"))
        self.assertEqual(process_identity(None, backend), (None, None))
        self.assertEqual(process_identity(13, backend), (None, None))

    def test_normalize_connection_maps_supported_values_and_skips_unknown_family(self) -> None:
        backend = FakeBackend([[]])
        with patch("system_monitor.platform.system", return_value="Windows"):
            normalized = normalize_connection(raw_connection(), backend, "2026-01-01T00:00:00Z")
        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual(normalized.system, "windows")
        self.assertEqual(normalized.protocol, "tcp")
        self.assertEqual(normalized.remote_port, 443)
        self.assertIsNone(normalize_connection(raw_connection(family=9999), backend, "now"))

    def test_collect_connections_filters_unconnected_and_deduplicates(self) -> None:
        connected = raw_connection()
        listening = raw_connection(remote=(), pid=None)
        backend = FakeBackend([[connected, connected, listening]])
        result = collect_connections(backend, observed_at_utc="now")
        self.assertEqual(len(result), 1)
        self.assertEqual(backend.kind, "inet")

        backend = FakeBackend([[listening]])
        included = collect_connections(
            backend, include_unconnected=True, observed_at_utc="now"
        )
        self.assertEqual(len(included), 1)
        self.assertIsNone(included[0].remote_address)

    def test_collect_connections_converts_access_denied_to_monitor_error(self) -> None:
        class DeniedBackend(FakeBackend):
            def net_connections(self, *, kind: str) -> list[SimpleNamespace]:
                raise FakeAccessDenied(kind)

        with self.assertRaises(MonitorError):
            collect_connections(DeniedBackend([[]]))

        class RuntimeFailureBackend(FakeBackend):
            def net_connections(self, *, kind: str) -> list[SimpleNamespace]:
                raise RuntimeError("GetExtendedTcpTable failed")

        with self.assertRaises(MonitorError):
            collect_connections(RuntimeFailureBackend([[]]))

    def test_connection_key_ignores_observation_time_and_process_label(self) -> None:
        first = sample_event()
        second = sample_event(observed_at_utc="later", process_name="renamed")
        self.assertEqual(connection_key(first), connection_key(second))


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class MonitorRuntimeTests(unittest.TestCase):
    def test_monitor_reports_initial_and_reappearing_connection_only(self) -> None:
        connection = raw_connection()
        backend = FakeBackend([[connection], [connection], [], [connection]])
        clock = FakeClock()
        emitted: list[LiveConnection] = []
        events = monitor_connections(
            MonitorConfig(duration=3, interval=1),
            backend=backend,
            emit=emitted.append,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
            timestamp_factory=lambda: f"t{backend.index}",
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events, tuple(emitted))
        self.assertEqual(events[0].observed_at_utc, "t0")
        self.assertEqual(events[1].observed_at_utc, "t3")

    def test_monitor_enforces_event_limit(self) -> None:
        backend = FakeBackend([[raw_connection(), raw_connection(pid=43)]])
        with self.assertRaises(MonitorError):
            monitor_connections(MonitorConfig(duration=0, max_events=1), backend=backend)

    def test_terminal_and_jsonl_rendering_are_safe_and_parseable(self) -> None:
        event = sample_event(process_name="bad\x1b[31m")
        terminal = render_connection_event(event)
        payload = render_jsonl((event,)).decode("utf-8")
        self.assertNotIn("\x1b", terminal)
        self.assertEqual(json.loads(payload)["remote_address"], "203[.]0[.]113[.]10")
        self.assertEqual(render_jsonl(()), b"")

    def test_report_directory_and_write_use_human_readable_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected_dir = monitor_directory(root, "2026-11-15T12:30:00.123Z", "windows")
            with patch("system_monitor.platform.system", return_value="Windows"):
                written = write_monitor_report(
                    (sample_event(),), root, "2026-11-15T12:30:00.123Z"
                )
            self.assertEqual(written.parent, expected_dir)
            self.assertEqual(written.name, "connections.jsonl")
            saved = json.loads(written.read_text(encoding="utf-8"))
            self.assertEqual(saved["pid"], 42)
            self.assertEqual(saved["remote_address"], "203[.]0[.]113[.]10")

    def test_main_supports_terminal_and_controlled_errors(self) -> None:
        with patch("system_monitor.monitor_connections", return_value=(sample_event(),)):
            with patch("system_monitor.write_monitor_report") as writer:
                self.assertEqual(main(["--duration", "0", "--mode", "terminal"]), 0)
                writer.assert_not_called()
        self.assertEqual(main(["--duration", "-1"]), 2)


if __name__ == "__main__":
    unittest.main()
