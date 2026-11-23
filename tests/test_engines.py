from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import AnalysisConfig
from engines import (
    PACKAGE_UNAVAILABLE,
    EngineError,
    engine_command,
    parse_engine_output,
    run_engine,
    scan_engines,
    trusted_executable,
)
from models import EngineRun, Finding
from pipeline import analyze_file
from reporting import render_json, render_pdf, render_terminal


class EngineAdapterTests(unittest.TestCase):
    def test_commands_use_trusted_programs_and_offline_options(self) -> None:
        with patch("engines.trusted_executable", return_value="/tools/fixed"):
            semgrep = engine_command("semgrep")
            self.assertIn("--metrics=off", semgrep)
            self.assertIn("--disable-version-check", semgrep)
            self.assertIn("--disable-nosem", semgrep)
            self.assertIn("--norc", engine_command("shellcheck"))
            self.assertIn("-NoProfile", engine_command("powershell-parser"))
        with patch("engines.trusted_executable", return_value=None):
            self.assertIsNone(engine_command("semgrep"))
            self.assertIsNone(engine_command("shellcheck"))
            self.assertIsNone(engine_command("powershell-parser"))
        for engine in ("yara", "esprima"):
            self.assertEqual(engine_command(engine)[:2], [sys.executable, "-I"])

    def test_executable_discovery_ignores_relative_path(self) -> None:
        with patch("engines.os.get_exec_path", return_value=[".", "relative"]):
            self.assertIsNone(trusted_executable("shellcheck"))
        with (
            patch("engines.os.get_exec_path", return_value=[str(Path(sys.executable).parent)]),
            patch("engines.shutil.which", return_value=sys.executable) as which,
        ):
            self.assertEqual(trusted_executable("shellcheck"), sys.executable)
            self.assertTrue(Path(which.call_args.args[0]).is_absolute())

    def test_runner_input_exit_code_timeout_and_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            command = [sys.executable, "-I", "-c"]
            program = "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.exit(7)"
            with (
                patch.dict(os.environ, {"INFA_SLED_API_KEY": "test-key"}),
                patch("engines.subprocess.Popen", wraps=subprocess.Popen) as popen,
            ):
                code, output = run_engine([*command, program], directory, b"example")
            self.assertIs(popen.call_args.kwargs["shell"], False)
            self.assertNotIn("INFA_SLED_API_KEY", popen.call_args.kwargs["env"])
            self.assertEqual((code, output), (7, "example"))
            self.assertEqual(list(directory.iterdir()), [])
            with self.assertRaisesRegex(EngineError, "czasu"):
                run_engine([*command, "import time; time.sleep(2)"], directory, b"", timeout=0.1)
            self.assertEqual(list(directory.iterdir()), [])
            for stream, limit_name in (
                ("stdout", "MAX_STDOUT_BYTES"), ("stderr", "MAX_STDERR_BYTES"),
            ):
                with self.subTest(stream=stream), patch(f"engines.{limit_name}", 16):
                    with self.assertRaisesRegex(EngineError, "wyjscia"):
                        program = f"import sys; sys.{stream}.write('x'*2000)"
                        run_engine([*command, program], directory, b"")
                    self.assertEqual(list(directory.iterdir()), [])

    def test_output_mapping_distinguishes_empty_partial_and_malformed(self) -> None:
        diagnostic = {"code": 2086, "line": 3, "level": "warning", "message": "Quote the expansion"}
        detections, partial = parse_engine_output("shellcheck", json.dumps([diagnostic]), "one\necho $x")
        self.assertEqual(
            (detections[0].rule_id, detections[0].line, detections[0].excerpt, detections[0].severity),
            ("SC2086", 2, "echo $x", "low"),
        )
        self.assertFalse(partial)
        diagnostic["level"] = "error"
        self.assertTrue(parse_engine_output("shellcheck", json.dumps([diagnostic]), "")[1])
        self.assertEqual(parse_engine_output("shellcheck", "[]", ""), ((), False))
        with self.assertRaises(ValueError):
            parse_engine_output("shellcheck", '[{"code":"2086"}]', "")

        payload = {
            "results": [{"check_id": "SEMGREP-JS-001", "start": {"line": 2}}],
            "errors": [], "paths": {"scanned": ["sample.js"]},
        }
        detections, partial = parse_engine_output("semgrep", json.dumps(payload), "one\ntwo")
        self.assertEqual((detections[0].tags, detections[0].excerpt), (("semgrep",), "two"))
        self.assertFalse(partial)
        payload["paths"]["scanned"] = []
        self.assertTrue(parse_engine_output("semgrep", json.dumps(payload), "one\ntwo")[1])
        with patch("engines.MAX_FINDINGS", 0):
            self.assertEqual(parse_engine_output("semgrep", json.dumps(payload), ""), ((), True))

    def test_unavailable_bad_output_and_failed_command_do_not_stop_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch(
            "engines.engine_command", side_effect=[["yara"], ["semgrep"], ["esprima"]],
        ), patch("engines.run_engine", side_effect=[(PACKAGE_UNAVAILABLE, ""), (2, ""), (0, "{")]):
            detections, statuses = scan_engines("", b"", "javascript", Path(temp), "original")
            self.assertEqual(detections, ())
            self.assertEqual([run.status for run in statuses], ["unavailable", "error", "error"])
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_powershell_guard_and_input_limit_precede_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch("engines.MAX_INPUT_BYTES", 100), patch(
            "engines.engine_command", return_value=["fixed"],
        ), patch("engines.run_engine") as run:
            text = "UsInG module 'local.psm1'\n"
            _, statuses = scan_engines(text, b"x" * 101, "powershell", Path(temp), "original")
            self.assertEqual([status.status for status in statuses], ["skipped", "skipped"])
            self.assertIn("5 MB", statuses[0].detail)
            self.assertIn("zasobow", statuses[1].detail)
            run.assert_not_called()

    def test_semgrep_only_receives_snapshot_and_trusted_local_rules(self) -> None:
        def fake_run(args: list[str], directory: Path, data: bytes) -> tuple[int, str]:
            self.assertEqual(args[-1], "sample.js")
            self.assertEqual((directory / "sample.js").read_bytes(), b"first\nsecond")
            self.assertEqual(data, b"")
            self.assertIn("rules", json.loads((directory / "rules.yml").read_text(encoding="utf-8")))
            return 0, '{"results":[],"errors":[],"paths":{"scanned":["sample.js"]}}'

        with tempfile.TemporaryDirectory() as temp, patch(
            "engines.engine_command", side_effect=[None, ["fixed"], None],
        ), patch("engines.run_engine", side_effect=fake_run):
            output = Path(temp) / "reports"
            findings, runs = scan_engines("first\r\nsecond", b"", "javascript", output, "original")
            self.assertEqual(findings, ())
            self.assertEqual([run.status for run in runs], ["unavailable", "ok", "unavailable"])
            self.assertEqual(list(output.iterdir()), [])

    def test_pipeline_combines_transformed_detections_and_reports_status(self) -> None:
        original_run = EngineRun("yara", "original", "unavailable", "Brak pakietu")
        decoded_run = EngineRun("yara", "deobfuscated", "ok")
        decoded = Finding("YARA-PS-001", "tytul", "high", "opis", 1, "dowod", ("yara",))
        with tempfile.TemporaryDirectory() as temp, patch(
            "pipeline.scan_engines", side_effect=[((), (original_run,)), ((decoded,), (decoded_run,))],
        ) as scan:
            path = Path(temp) / "sample.ps1"
            path.write_bytes(b'$x="SUVYIGh0dHBzOi8vYmFkLmV4YW1wbGUvYQ=="')
            result = analyze_file(path, AnalysisConfig(output_dir=Path(temp) / "out"))
            self.assertEqual(scan.call_args.args[-1], "deobfuscated")
            self.assertEqual(result.engine_runs, (original_run, decoded_run))
            finding = next(item for item in result.findings if item.rule_id == decoded.rule_id)
            self.assertIn("deobfuscated", finding.tags)
            self.assertEqual(json.loads(render_json(result))["engine_runs"][0]["status"], "unavailable")
            self.assertIn("SILNIKI ANALIZY STATYCZNEJ", render_terminal(result))
            self.assertIn(b"SILNIKI ANALIZY STATYCZNEJ", render_pdf(result))


@unittest.skipUnless(os.environ.get("TEST_STATIC_ENGINES") == "1", "requires installed engines")
class InstalledEngineTests(unittest.TestCase):
    def test_rules_match_real_tools_on_positive_and_negative_samples(self) -> None:
        cases = (
            ("powershell", "PSAST-001", "& 'Invoke-Expression' '1'", "'Invoke-Expression'"),
            ("powershell", "PSAST-002", "[ScriptBlock]::Create('1')", "'[ScriptBlock]::Create'"),
            ("powershell", "YARA-PS-001", "# Invoke-Expression DownloadString", "# DownloadString"),
            ("javascript", "YARA-JS-001", "// child_process and execSync", "// child_process"),
            ("bash", "YARA-SH-001", "# bash -i and /dev/tcp/", "# /dev/tcp/"),
            ("javascript", "ESPRIMA-JS-001", 'globalThis["eval"]("1")', 'const s = "eval(1)";'),
            (
                "javascript", "SEMGREP-JS-001",
                'require("child_process").exec("true");',
                '// require("child_process").exec("true");',
            ),
            ("bash", "SEMGREP-SH-001", 'eval "true"', '# eval "true"'),
            (
                "bash", "SC2086",
                '#!/bin/bash\nvalue="a b"\necho $value',
                '#!/bin/bash\nvalue="a b"\necho "$value"',
            ),
        )
        with tempfile.TemporaryDirectory() as temp:
            for language, rule_id, positive, negative in cases:
                for source, expected in ((positive, True), (negative, False)):
                    with self.subTest(rule_id=rule_id, positive=expected):
                        findings, runs = scan_engines(
                            source, source.encode("utf-8"), language, Path(temp), "original",
                        )
                        self.assertTrue(all(run.status == "ok" for run in runs), runs)
                        self.assertEqual(rule_id in {finding.rule_id for finding in findings}, expected)

    def test_esprima_parse_failure_and_shellcheck_sample_directive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            findings, runs = scan_engines("const =;", b"const =;", "javascript", Path(temp), "original")
            self.assertEqual(next(run.status for run in runs if run.engine == "esprima"), "partial")
            self.assertFalse(any("esprima" in item.tags for item in findings))
            source = (
                '# shellcheck disable=SC2086 source=other.sh\n'
                'source missing.sh\nvalue="a b"\necho $value'
            )
            findings, runs = scan_engines(source, source.encode(), "bash", Path(temp), "original")
            self.assertEqual(next(run.status for run in runs if run.engine == "shellcheck"), "ok")
            self.assertIn(("SC2086", 4), {(item.rule_id, item.line) for item in findings})
            self.assertNotIn("SC1091", {item.rule_id for item in findings})
