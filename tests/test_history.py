from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

from config import AnalysisConfig
from connections import assess_connections, correlate_iocs
from errors import ConfigurationError, InputFileError
from fileio import read_script
from history import (
    MAX_BYTES, assess_execution, audit_events, canonical_path, collect_system_history,
    normalized_event, parse_history, read_history_log, run_history_command,
    script_argument, source_summary, windows_events,
)
from main import build_parser, config_from_args
from models import ConnectionMatch, ConnectionRecord, HistoryEvent, HistorySource, IOC
from pipeline import analyze_file
from reporting import history_report_lines, pdf_lines, render_json, render_terminal


def xml_event(number: int, data: str, provider: str = "Microsoft-Windows-Sysmon") -> str:
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}"/><EventID>{number}</EventID>'
        '<TimeCreated SystemTime="2026-11-15T10:00:00Z"/><Computer>HOST</Computer></System>'
        f'<EventData>{data}</EventData></Event>'
    )


class HistoryParsingTests(unittest.TestCase):
    def test_windows_provider_direction_and_event_semantics(self) -> None:
        network = '<Data Name="DestinationIp">192.0.2.1</Data><Data Name="Initiated">true</Data>'
        guid = '<Data Name="ProcessGuid">{GUID}</Data>'
        event = windows_events(xml_event(3, network + guid), "sysmon")[0]
        self.assertEqual((event.event_type, event.address, event.process_key), ("connected", "192.0.2.1", "HOST|{GUID}"))
        self.assertEqual(windows_events(xml_event(3, network.replace("true", "false")), "x"), ())
        self.assertEqual(windows_events(xml_event(3, network, "unknown-provider"), "x"), ())
        for number, expected in ((5156, "allowed"), (5157, "blocked")):
            data = '<Data Name="DestAddress">192.0.2.1</Data><Data Name="Direction">%%14593</Data>'
            self.assertEqual(windows_events(xml_event(number, data, "Microsoft-Windows-Security-Auditing"), "x")[0].event_type, expected)
            self.assertFalse(windows_events(xml_event(number, data.replace("14593", "14592"), "Microsoft-Windows-Security-Auditing"), "x"))
        self.assertEqual(windows_events(xml_event(1, guid), "x")[0].event_type, "process-start")
        self.assertEqual(windows_events(xml_event(22, '<Data Name="QueryName">bad.example</Data>'), "x")[0].event_type, "dns-query")
        self.assertEqual(windows_events(xml_event(4688, '', "Microsoft-Windows-Security-Auditing"), "x")[0].event_type, "process-start")
        self.assertEqual(windows_events(xml_event(4104, '', "Microsoft-Windows-PowerShell"), "x")[0].event_type, "script-block")
        self.assertEqual(windows_events('<Events/>', "x"), ())
        for text in ('<broken>', '<!DOCTYPE x><Events/>', '<!ENTITY x "value"><Events/>'):
            with self.assertRaises(InputFileError):
                windows_events(text, "x")

    def test_normalized_contract_validates_types_and_ignores_unknown_ids(self) -> None:
        self.assertIsNone(normalized_event({"event_type": []}, "x"))
        event = normalized_event({"event_type": "process-start", "argv": ["bash", "/x.sh"], "pid": "1"}, "x")
        self.assertIsNone(event.process_key)
        self.assertEqual(event.argv, ("bash", "/x.sh"))
        for data in ({"event_type": "connected", "address": 4}, {"event_type": "process-start", "argv": "bash"}):
            with self.assertRaises(InputFileError):
                normalized_event(data, "x")

    def test_parse_formats_and_no_network_proof_from_plain_mentions(self) -> None:
        text = '2026-11-15T10:00:00Z action=blocked destination_ip=192.0.2.1\nmentions https://bad.example/a'
        events = parse_history(text, "log")
        self.assertEqual([event.event_type for event in events], ["blocked", "mentioned"])
        self.assertEqual(source_summary("x", events).network_event_count, 1)
        self.assertEqual(source_summary("x", ()).status, "empty")
        self.assertEqual(parse_history('event_type,address\nconnected,192.0.2.1\n', "csv")[0].event_type, "connected")
        self.assertEqual(parse_history(xml_event(1, ''), "xml")[0].event_type, "process-start")
        journal = json.dumps({"MESSAGE": "[UFW BLOCK] IN= OUT=eth0 SRC=192.0.2.2 DST=192.0.2.1", "__REALTIME_TIMESTAMP": "1794736800000000"})
        self.assertEqual(parse_history(journal, "journal")[0].address, "192.0.2.1")
        self.assertIsNotNone(parse_history(journal, "journal")[0].timestamp)
        nested = json.dumps({"MESSAGE": xml_event(22, '<Data Name="QueryName">bad.example</Data>')})
        self.assertEqual(parse_history(nested, "journal")[0].event_type, "dns-query")
        for bad in ('{bad', '[]\n{bad', '{"event_type":"connected","address":4}', '{"MESSAGE":"type=SYSCALL msg=audit(1:1) broken'):
            with self.assertRaises(InputFileError):
                parse_history(bad, "x")
        with self.assertRaises(InputFileError):
            parse_history("a\nb", "x", max_lines=1)

    def test_read_history_bounds_missing_binary_and_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log.txt"
            with self.assertRaises(InputFileError):
                read_history_log(path)
            path.write_bytes(b"\xff\x00")
            with self.assertRaises(InputFileError):
                read_history_log(path)
            path.write_text("action=connected dst=192.0.2.1", encoding="utf-8-sig")
            self.assertEqual(read_history_log(path)[0].event_type, "connected")
            with self.assertRaises(InputFileError):
                read_history_log(path, max_bytes=2)
            path.write_text(xml_event(1, ''), encoding="utf-16")
            self.assertEqual(read_history_log(path)[0].event_type, "process-start")

    def test_audit_groups_successful_exec_and_rejects_failed_or_other_syscalls(self) -> None:
        raw = (
            'type=SYSCALL msg=audit(1794736800.1:12): arch=c000003e syscall=59 success=yes exe="/bin/bash"\n'
            'type=EXECVE msg=audit(1794736800.1:12): argc=2 a0="bash" a1=2F746D702F782E7368\n'
            'type=CWD msg=audit(1794736800.1:12): cwd="/tmp"\n'
        )
        events = audit_events(raw, "audit")
        self.assertEqual(events[0].argv, ("bash", "/tmp/x.sh"))
        self.assertEqual(events[0].cwd, "/tmp")
        self.assertEqual(audit_events(raw.replace("success=yes", "success=no"), "x"), ())
        self.assertEqual(audit_events(raw.replace("syscall=59", "syscall=2"), "x"), ())
        self.assertEqual(audit_events(raw.replace("a1=2F746D702F782E7368", "a1=XYZ"), "x"), ())
        journal = '\n'.join(json.dumps({"MESSAGE": line}) for line in raw.splitlines())
        self.assertEqual(parse_history(journal, "journal")[0].argv, events[0].argv)
        split_hosts = raw.replace('type=SYSCALL ', 'node=HOST-A type=SYSCALL ').replace('type=EXECVE ', 'node=HOST-B type=EXECVE ')
        self.assertEqual(audit_events(split_hosts, "x"), ())


class EvidenceTests(unittest.TestCase):
    def test_connection_semantics_host_matching_and_deduplication(self) -> None:
        iocs = (IOC("ip", "192.0.2.1", ()), IOC("url", "https://192.0.2.1/a", ()))
        record = ConnectionRecord(None, "192.0.2.1", "x", "x", "connected")
        matches = correlate_iocs(iocs, (record, record))
        self.assertEqual(len(matches), 2)
        checks = assess_connections(iocs, matches, 1)
        self.assertEqual([check.status for check in checks], ["confirmed", "host-only"])
        cases = {"mentioned": "mentioned-only", "dns-query": "dns-only", "allowed": "allowed", "blocked": "blocked", "url-request": "request-observed"}
        for kind, status in cases.items():
            match = ConnectionMatch("ip", "192.0.2.1", None, "x", "x", kind)
            self.assertEqual(assess_connections(iocs[:1], (match,), 1)[0].status, status)
        blocked = replace(matches[0], event_type="blocked")
        self.assertEqual(assess_connections(iocs[:1], (blocked, matches[0]), 1)[0].status, "confirmed")

    def test_script_path_and_interpreter_arguments_are_exact(self) -> None:
        self.assertEqual(canonical_path(r"C:\Work\x.ps1"), r"c:\work\x.ps1")
        self.assertEqual(canonical_path("x.sh", "/tmp"), "/tmp/x.sh")
        self.assertEqual(canonical_path("x.sh"), "")
        self.assertNotEqual(canonical_path("/Tmp/x.sh"), canonical_path("/tmp/x.sh"))
        base = HistoryEvent("process-start", None, "x", image="powershell.exe")
        self.assertEqual(script_argument(replace(base, command_line='powershell.exe -File "C:\\My Files\\x.ps1"')), r"C:\My Files\x.ps1")
        for command in ('powershell.exe -Command echo -File C:\\x.ps1', 'powershell.exe -File', 'powershell.exe -EncodedCommand AAA'):
            self.assertEqual(script_argument(replace(base, command_line=command)), "")
        self.assertEqual(script_argument(replace(base, image="bash", command_line="bash '/tmp/my script.sh'")), "/tmp/my script.sh")
        self.assertEqual(script_argument(replace(base, image="/bin/bash", argv=("/tmp/first.sh", "/tmp/target.sh"))), "/tmp/first.sh")
        for image, argv in (("bash", ("bash", "-c", "echo /tmp/x.sh")), ("node", ("node", "-e", "/tmp/x.js")), ("cat", ("cat", "/tmp/x.sh"))):
            self.assertEqual(script_argument(replace(base, image=image, argv=argv)), "")

    def test_execution_identity_no_basename_and_no_scriptblock_confirmation(self) -> None:
        script = read_script(Path(__file__).resolve().parents[1] / "examples" / "benign.js")
        event = HistoryEvent("process-start", None, "x", image="node", argv=("node", str(script.path)))
        result = assess_execution(script, (event, event), 1)
        self.assertEqual((result.status, len(result.matches)), ("confirmed", 1))
        self.assertIn("brak potwierdzenia historycznej zawartosci", result.matches[0].detail)
        for negative in (replace(event, argv=("node", script.path.name)), replace(event, event_type="script-block", script_path=str(script.path)), replace(event, argv=("node", str(script.path) + ".bak"))):
            self.assertEqual(assess_execution(script, (negative,), 1).status, "not-observed")
        hashed = replace(event, argv=(), script_sha256=script.hashes.sha256)
        self.assertEqual(assess_execution(script, (hashed,), 1).matches[0].identity, "script-sha256")
        self.assertEqual(assess_execution(script, (), 0).status, "not-checked")
        with self.assertRaises(InputFileError):
            assess_execution(script, (), 0, original_path="relative.js")

    def test_pipeline_demo_reports_attribution_and_defangs_new_fields(self) -> None:
        root = Path(__file__).resolve().parents[1]
        script = root / "examples" / "suspicious_obfuscated.ps1"
        log = root / "examples" / "history_demo.jsonl"
        original = script.read_bytes()
        result = analyze_file(script, AnalysisConfig(execution_logs=(log,), connection_logs=(log,), original_script_path=r"C:\demo\suspicious_obfuscated.ps1"))
        self.assertEqual(script.read_bytes(), original)
        self.assertEqual(len(result.history_sources), 1)
        self.assertEqual(result.execution_check.status, "confirmed")
        self.assertEqual(result.execution_check.matches[0].identity, "script-path")
        matches = {match.ioc_value: match for match in result.connection_matches if not match.event_type.startswith("host-")}
        self.assertTrue(matches["192.0.2.10"].script_related)
        self.assertFalse(matches["https://bad.example/a"].script_related)
        rendered = render_terminal(result)
        self.assertIn("ZABLOKOWANA PROBA", rendered)
        self.assertIn("TAK - zarejestrowano wywolanie skryptu", rendered)
        self.assertIn("CZY SKRYPT BYL URUCHAMIANY", '\n'.join(pdf_lines(result)))
        self.assertTrue(history_report_lines(result))
        payload = render_json(result).decode()
        self.assertNotIn("https://bad.example", payload)
        self.assertNotIn("192.0.2.10", payload)
        self.assertIn('"schema_version": "1.3"', payload)


class SystemHistoryTests(unittest.TestCase):
    def test_command_uses_no_shell_and_handles_timeout_size_utf16(self) -> None:
        def fake_process(args, **kwargs):
            self.assertFalse(kwargs["shell"])
            kwargs["stdout"].write('<Events/>'.encode("utf-16"))
            kwargs["stdout"].flush()
            context = MagicMock()
            context.__enter__.return_value = context
            context.returncode = 0
            context.poll.return_value = 0
            return context
        with patch("history.subprocess.Popen", side_effect=fake_process):
            self.assertEqual(run_history_command(["wevtutil", "qe"]), '<Events/>')
        with patch("history.subprocess.Popen", side_effect=OSError("missing")):
            with self.assertRaises(InputFileError):
                run_history_command(["x"])
        def too_large(args, **kwargs):
            context = fake_process(args, **kwargs)
            kwargs["stdout"].write(b"x" * (MAX_BYTES + 1))
            kwargs["stdout"].flush()
            return context
        with patch("history.subprocess.Popen", side_effect=too_large):
            with self.assertRaises(InputFileError):
                run_history_command(["x"])
        context = MagicMock()
        context.__enter__.return_value = context
        context.poll.return_value = None
        with patch("history.subprocess.Popen", return_value=context), patch("history.time.monotonic", side_effect=[0, 11]):
            with self.assertRaises(InputFileError):
                run_history_command(["x"])
        context.kill.assert_called_once()
        context.returncode = 5
        context.poll.return_value = 5
        with patch("history.subprocess.Popen", return_value=context):
            with self.assertRaisesRegex(InputFileError, 'brak uprawnien'):
                run_history_command(["x"])

    def test_windows_sources_isolate_errors_and_have_explicit_limits(self) -> None:
        with patch("history.platform.system", return_value="Windows"), patch("history.run_history_command", side_effect=[InputFileError("denied"), '<Events/>' ]) as runner:
            events, sources = collect_system_history(12, 50)
        self.assertEqual(events, ())
        self.assertEqual([source.status for source in sources], ["unavailable", "empty"])
        self.assertIn('/c:50', runner.call_args_list[0].args[0])
        self.assertTrue(any("43200000" in arg for arg in runner.call_args_list[0].args[0]))
        with self.assertRaises(InputFileError):
            collect_system_history(0, 1000)

    def test_linux_journal_and_unsupported_os_and_pipeline_partial_source(self) -> None:
        audit = HistoryEvent("process-start", datetime.now(timezone.utc).isoformat(), "audit", image="bash", argv=("bash", "/tmp/x.sh"))
        with patch("history.platform.system", return_value="Linux"), patch("history.read_history_log", return_value=(audit,)), patch("history.run_history_command", return_value='{"MESSAGE":"[UFW BLOCK] IN= OUT=eth0 DST=192.0.2.1"}') as runner:
            events, sources = collect_system_history()
        self.assertEqual(events[0].event_type, "blocked")
        self.assertEqual(sources[1].execution_event_count, 1)
        self.assertEqual(events[-1], audit)
        self.assertIn('--since=-24h', runner.call_args.args[0])
        with patch("history.platform.system", return_value="Darwin"):
            self.assertEqual(collect_system_history()[1][0].status, "unavailable")
        root = Path(__file__).resolve().parents[1]
        with patch("pipeline.collect_system_history", return_value=((), (HistorySource("Security", "unavailable", 0, detail="denied"),))):
            result = analyze_file(root / "examples" / "benign.js", AnalysisConfig(system_history=True))
        self.assertEqual(result.execution_check.status, "not-checked")
        self.assertTrue(all(check.status == "not-checked" for check in result.connection_checks))
        self.assertTrue(any("denied" in warning for warning in result.warnings))

    def test_cli_and_configuration_limits(self) -> None:
        args = build_parser().parse_args(["x.sh", "--system-history", "--history-hours", "12", "--history-max-events", "50", "--execution-log", "audit.log"])
        config = config_from_args(args)
        self.assertTrue(config.system_history)
        self.assertEqual(config.history_hours, 12)
        self.assertEqual(config.execution_logs, (Path("audit.log"),))
        for values in ({"history_hours": 0}, {"history_hours": 8761}, {"history_max_events": 0}, {"history_max_events": 10001}):
            with self.assertRaises(ConfigurationError):
                AnalysisConfig(**values)
