from __future__ import annotations

import json
import socket
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError

from connections import correlate_iocs, extract_timestamp, parse_connection_log
from errors import InputFileError
from models import ConnectionRecord, IOC, TimestampInfo
from reputation import (
    check_reputation,
    parse_urlhaus,
    parse_virustotal,
    read_json,
    urlhaus_request,
    virustotal_request,
)
from timing import (
    NTP_EPOCH_DELTA,
    format_utc,
    get_timestamp,
    query_ntp,
    system_timestamp,
)


class ConnectionTests(unittest.TestCase):
    def test_extract_timestamp_handles_present_and_missing_value(self) -> None:
        self.assertEqual(
            extract_timestamp("2026-11-15T12:13:14Z dst=8.8.8.8"),
            "2026-11-15T12:13:14Z",
        )
        self.assertIsNone(extract_timestamp("dst=8.8.8.8"))

    def test_parse_connection_log_extracts_records_from_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.jsonl"
            path.write_text(
                '{"timestamp":"2026-11-15T12:13:14Z","dst":"8.8.8.8"}\n'
                "2026-11-15 13:00:00 host=bad[.]example\n",
                encoding="utf-8",
            )
            records = parse_connection_log(path)
            self.assertEqual({item.address for item in records}, {"8.8.8.8", "bad.example"})
            self.assertEqual(records[0].timestamp, "2026-11-15T12:13:14Z")

    def test_parse_connection_log_enforces_file_and_line_limits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(InputFileError):
                parse_connection_log(root / "missing.log")
            path = root / "connections.log"
            path.write_text("8.8.8.8\n1.1.1.1\n", encoding="utf-8")
            with self.assertRaises(InputFileError):
                parse_connection_log(path, max_bytes=3)
            with self.assertRaises(InputFileError):
                parse_connection_log(path, max_lines=1)

    def test_correlate_iocs_deduplicates_exact_matches(self) -> None:
        iocs = (IOC("ip", "8.8.8.8", ("original",)),)
        record = ConnectionRecord("2026-01-01T00:00:00Z", "8.8.8.8", "log", "dst=8.8.8.8")
        matches = correlate_iocs(iocs, (record, record))
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].ioc_kind, "ip")
        self.assertEqual(correlate_iocs(iocs, (ConnectionRecord(None, "1.1.1.1", "x", "x"),)), ())


class FakeSocket:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.timeout = None
        self.sent = None
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendto(self, data: bytes, address: tuple[str, int]) -> None:
        self.sent = (data, address)

    def recvfrom(self, size: int) -> tuple[bytes, tuple[str, int]]:
        return self.response[:size], ("127.0.0.1", 123)

    def close(self) -> None:
        self.closed = True


class TimingTests(unittest.TestCase):
    def test_format_utc_and_system_timestamp(self) -> None:
        moment = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        self.assertEqual(format_utc(moment), "2026-01-02T03:04:05Z")
        stamp = system_timestamp(moment)
        self.assertEqual(stamp.iso_utc, "2026-01-02T03:04:05Z")
        self.assertFalse(stamp.synchronized)

    def test_query_ntp_parses_response_and_closes_socket(self) -> None:
        response = bytearray(48)
        response[40:48] = struct.pack("!II", NTP_EPOCH_DELTA + 10, 0)
        fake = FakeSocket(bytes(response))
        stamp = query_ntp("time.example", 2.0, socket_factory=lambda *_: fake)
        self.assertEqual(stamp.iso_utc, "1970-01-01T00:00:10Z")
        self.assertTrue(stamp.synchronized)
        self.assertEqual(fake.sent[1], ("time.example", 123))
        self.assertTrue(fake.closed)

    def test_query_ntp_rejects_invalid_input_and_short_response(self) -> None:
        with self.assertRaises(ValueError):
            query_ntp("", timeout=1)
        fake = FakeSocket(b"short")
        with self.assertRaises(OSError):
            query_ntp("time.example", socket_factory=lambda *_: fake)
        self.assertTrue(fake.closed)

    def test_get_timestamp_uses_system_success_or_fallback(self) -> None:
        self.assertEqual(get_timestamp().source, "system")
        expected = TimestampInfo("2026-01-01T00:00:00Z", "ntp", "time.example", True)
        self.assertEqual(get_timestamp("time.example", ntp_query=lambda *_: expected), expected)

        def failure(*_: object) -> TimestampInfo:
            raise socket.gaierror("offline")

        fallback = get_timestamp("bad.example", ntp_query=failure)
        self.assertEqual(fallback.source, "system-fallback")
        self.assertEqual(fallback.ntp_server, "bad.example")


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self.payload[:size]


class ReputationTests(unittest.TestCase):
    def test_virustotal_request_builds_resources_and_private_header(self) -> None:
        ip_request = virustotal_request(IOC("ip", "8.8.8.8", ()), "secret")
        domain_request = virustotal_request(IOC("domain", "bad.example", ()), "secret")
        url_request = virustotal_request(IOC("url", "https://bad.example/a", ()), "secret")
        self.assertTrue(ip_request.full_url.endswith("/ip_addresses/8.8.8.8"))
        self.assertTrue(domain_request.full_url.endswith("/domains/bad.example"))
        self.assertIn("/urls/", url_request.full_url)
        self.assertEqual(ip_request.headers["X-apikey"], "secret")
        with self.assertRaises(ValueError):
            virustotal_request(IOC("hash", "abc", ()), "secret")

    def test_urlhaus_request_uses_post_and_auth_header(self) -> None:
        request = urlhaus_request(IOC("url", "https://bad.example/a", ()), "secret")
        host_request = urlhaus_request(IOC("domain", "bad.example", ()), "secret")
        self.assertEqual(request.method, "POST")
        self.assertIn(b"url=", request.data)
        self.assertIn(b"host=", host_request.data)
        self.assertEqual(request.headers["Auth-key"], "secret")
        with self.assertRaises(ValueError):
            urlhaus_request(IOC("hash", "abc", ()), "secret")

    def test_read_json_validates_shape_and_size(self) -> None:
        request = virustotal_request(IOC("ip", "8.8.8.8", ()), "key")
        parsed = read_json(request, 1, opener=lambda *_args, **_kwargs: FakeResponse({"ok": True}))
        self.assertTrue(parsed["ok"])
        with self.assertRaises(ValueError):
            read_json(request, 1, opener=lambda *_args, **_kwargs: FakeResponse([]))
        with self.assertRaises(ValueError):
            read_json(request, 1, opener=lambda *_args, **_kwargs: FakeResponse(b"x" * 1_000_001))

    def test_parse_provider_payloads(self) -> None:
        ioc = IOC("domain", "bad.example", ())
        vt = parse_virustotal(
            ioc,
            {
                "data": {
                    "attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1}},
                    "links": {"self": "https://reference"},
                }
            },
        )
        self.assertEqual(vt.status, "malicious")
        self.assertEqual(vt.malicious_count, 3)
        listed = parse_urlhaus(ioc, {"query_status": "ok", "urlhaus_reference": "https://ref"})
        missing = parse_urlhaus(ioc, {"query_status": "no_results"})
        self.assertEqual(listed.status, "listed")
        self.assertEqual(missing.status, "not-listed")

    def test_check_reputation_handles_success_errors_and_provider_validation(self) -> None:
        ioc = IOC("domain", "bad.example", ())
        payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
        success = check_reputation(
            (ioc,),
            "virustotal",
            "key",
            opener=lambda *_args, **_kwargs: FakeResponse(payload),
        )
        self.assertEqual(success[0].status, "not-detected")

        def offline(*_args: object, **_kwargs: object) -> FakeResponse:
            raise URLError("offline")

        failure = check_reputation((ioc,), "urlhaus", "key", opener=offline)
        self.assertTrue(failure[0].status.startswith("error:"))
        with self.assertRaises(ValueError):
            check_reputation((ioc,), "other", "key")


if __name__ == "__main__":
    unittest.main()
