from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from config import AnalysisConfig
from errors import ConfigurationError, InputFileError, UnsupportedLanguageError
from fileio import (
    compute_hashes,
    decode_script,
    detect_language,
    modified_at_utc,
    read_script,
)
from models import Hashes, to_primitive


class ModelsTests(unittest.TestCase):
    def test_to_primitive_handles_dataclass_paths_dates_and_collections(self) -> None:
        value = {
            "hashes": Hashes("a", "b", "c"),
            "path": Path("sample.ps1"),
            "when": datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc),
            "items": (1, 2),
        }
        converted = to_primitive(value)
        self.assertEqual(converted["hashes"]["sha256"], "a")
        self.assertEqual(converted["path"], "sample.ps1")
        self.assertEqual(converted["when"], "2026-01-02T03:04:00Z")
        self.assertEqual(converted["items"], [1, 2])


class ConfigTests(unittest.TestCase):
    def test_config_normalizes_values(self) -> None:
        config = AnalysisConfig(
            output_dir="reports",
            report_formats=("JSON", "json", "pdf"),
            connection_logs=("connections.log",),
        )
        self.assertEqual(config.output_dir, Path("reports"))
        self.assertEqual(config.report_formats, ("json", "pdf"))
        self.assertEqual(config.connection_logs, (Path("connections.log"),))

    def test_config_rejects_invalid_or_implicit_network_settings(self) -> None:
        invalid = (
            {"report_formats": ()},
            {"report_formats": ("xml",)},
            {"max_file_size": 0},
            {"request_timeout": 0},
            {"reputation_provider": "other"},
            {"ntp_server": "time.example"},
            {
                "enable_network": True,
                "reputation_provider": "virustotal",
                "reputation_api_key": None,
            },
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ConfigurationError):
                AnalysisConfig(**values)

    def test_config_allows_explicit_network_configuration(self) -> None:
        config = AnalysisConfig(
            enable_network=True,
            ntp_server="time.example",
            reputation_provider="urlhaus",
            reputation_api_key="secret",
        )
        self.assertTrue(config.enable_network)


class FileIoTests(unittest.TestCase):
    def test_compute_hashes_uses_required_algorithms(self) -> None:
        hashes = compute_hashes(b"abc")
        self.assertEqual(hashes.sha256, hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(hashes.sha1, hashlib.sha1(b"abc").hexdigest())
        self.assertEqual(hashes.md5, hashlib.md5(b"abc").hexdigest())

    def test_decode_script_supports_utf_bom_and_cp1250(self) -> None:
        self.assertEqual(decode_script(b"hello"), ("hello", "utf-8"))
        utf16 = "czesc".encode("utf-16")
        self.assertEqual(decode_script(utf16), ("czesc", "utf-16"))
        self.assertEqual(decode_script("zażółć".encode("cp1250")), ("zażółć", "cp1250"))

    def test_decode_script_rejects_binary_data(self) -> None:
        with self.assertRaises(InputFileError):
            decode_script(b"MZ\x00binary")

    def test_detect_language_uses_extension_shebang_and_content(self) -> None:
        self.assertEqual(detect_language(Path("x.ps1"), "anything"), "powershell")
        self.assertEqual(detect_language(Path("x"), "#!/usr/bin/env node\nconst x=1"), "javascript")
        self.assertEqual(detect_language(Path("x"), "#!/bin/bash\necho ok"), "bash")
        self.assertEqual(detect_language(Path("x"), "$env:PATH"), "powershell")

    def test_detect_language_rejects_unknown_content(self) -> None:
        with self.assertRaises(UnsupportedLanguageError):
            detect_language(Path("README"), "plain prose")

    def test_modified_at_utc_and_read_script(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.js"
            original = b"const url = 'https://evil.example/a';\n"
            path.write_bytes(original)
            timestamp = modified_at_utc(path)
            script = read_script(path)
            self.assertTrue(timestamp.endswith("Z"))
            self.assertEqual(script.raw, original)
            self.assertEqual(script.language, "javascript")
            self.assertEqual(script.modified_at_utc, timestamp)

    def test_read_script_rejects_missing_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(InputFileError):
                read_script(root / "missing.ps1")
            path = root / "large.sh"
            path.write_text("echo too large", encoding="utf-8")
            with self.assertRaises(InputFileError):
                read_script(path, max_bytes=4)


if __name__ == "__main__":
    unittest.main()
