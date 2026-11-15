from __future__ import annotations

import base64
import unittest

from infa_sled.ioc import extract_iocs, merge_iocs, normalize_ioc
from infa_sled.models import IOC
from infa_sled.obfuscation import (
    decode_base64_literal,
    decode_escaped_literals,
    deobfuscate,
    detect_obfuscation,
    printable_ratio,
    simplify_string_concatenations,
)
from infa_sled.rules import default_rules, excerpt_for, line_number, scan_suspicious


class RulesTests(unittest.TestCase):
    def test_default_rules_have_unique_stable_ids(self) -> None:
        rules = default_rules()
        self.assertGreaterEqual(len(rules), 10)
        self.assertEqual(len({rule.rule_id for rule in rules}), len(rules))

    def test_line_number_and_excerpt_are_bounded(self) -> None:
        text = "first\n  second suspicious content  \nthird"
        start = text.index("suspicious")
        self.assertEqual(line_number(text, start), 2)
        self.assertEqual(excerpt_for(text, start, start + 10), "second suspicious content")
        self.assertEqual(len(excerpt_for("x" * 300, 0, 1, limit=20)), 20)

    def test_scan_suspicious_respects_language_and_orders_findings(self) -> None:
        powershell = "Invoke-WebRequest https://bad.example\nIEX $payload"
        findings = scan_suspicious(powershell, "powershell")
        self.assertEqual([item.line for item in findings], [1, 2])
        self.assertIn("PS-NET-001", {item.rule_id for item in findings})
        self.assertEqual(scan_suspicious("eval('x')", "bash"), ())
        duplicate_line = scan_suspicious("child_process.exec('x')", "javascript")
        self.assertEqual([item.rule_id for item in duplicate_line], ["JS-PROC-001"])


class ObfuscationTests(unittest.TestCase):
    def test_printable_ratio_handles_empty_and_text(self) -> None:
        self.assertEqual(printable_ratio(""), 0.0)
        self.assertEqual(printable_ratio("abc\n"), 1.0)
        self.assertLess(printable_ratio("a\x00"), 1.0)

    def test_decode_base64_literal_accepts_text_and_rejects_noise(self) -> None:
        encoded = base64.b64encode(b"Invoke-Expression test").decode("ascii")
        self.assertEqual(decode_base64_literal(encoded), "Invoke-Expression test")
        self.assertIsNone(decode_base64_literal("not_base64!!!!!"))
        self.assertIsNone(decode_base64_literal("A" * 1000, max_decoded_bytes=10))

    def test_detect_obfuscation_finds_supported_signals(self) -> None:
        encoded = base64.b64encode(b"https://malware.example/payload").decode("ascii")
        text = encoded + "\n'\\x41\\x42'\n'\\u0041\\u0042'\n'a'+'b'+'c'\n" + "x" * 501
        kinds = {item.kind for item in detect_obfuscation(text)}
        self.assertEqual(
            kinds,
            {"base64", "hex-escapes", "unicode-escapes", "string-concatenation", "long-line"},
        )

    def test_decode_escaped_literals_records_transformations(self) -> None:
        decoded, changes = decode_escaped_literals("x='\\x41\\u0042'")
        self.assertEqual(decoded, "x='AB'")
        self.assertEqual(len(changes), 2)
        self.assertEqual({item.kind for item in changes}, {"escaped-character"})

    def test_simplify_string_concatenations_is_bounded(self) -> None:
        decoded, changes = simplify_string_concatenations("'a' + 'b' + 'c'")
        self.assertEqual(decoded, "'abc'")
        self.assertEqual(len(changes), 2)
        limited, limited_changes = simplify_string_concatenations("'a'+'b'+'c'", max_passes=1)
        self.assertEqual(limited, "'ab'+'c'")
        self.assertEqual(len(limited_changes), 1)

    def test_deobfuscate_decodes_without_executing(self) -> None:
        encoded = base64.b64encode(b"IEX https://bad.example").decode("ascii")
        decoded, changes = deobfuscate(f"$x='{encoded}'")
        self.assertIn("IEX https://bad.example", decoded)
        self.assertIn("base64", {item.kind for item in changes})


class IocTests(unittest.TestCase):
    def test_normalize_ioc_supports_all_types_and_rejects_unknown(self) -> None:
        self.assertEqual(normalize_ioc("ip", "8.8.8.8"), "8.8.8.8")
        self.assertEqual(normalize_ioc("domain", "EXAMPLE.COM."), "example.com")
        self.assertEqual(
            normalize_ioc("url", "HTTPS://Example.COM:443/a?q=1#fragment"),
            "https://example.com:443/a?q=1",
        )
        with self.assertRaises(ValueError):
            normalize_ioc("hash", "abc")
        with self.assertRaises(ValueError):
            normalize_ioc("url", "ftp://example.com/file")

    def test_extract_iocs_validates_ips_and_avoids_url_host_duplicate(self) -> None:
        text = (
            "Visit https://Bad.Example/a, then 8.8.8.8 and standalone.example.org; "
            "ignore 999.1.1.1, console.log(value), and the filename node.js"
        )
        iocs = extract_iocs(text, "original")
        values = {(item.kind, item.value) for item in iocs}
        self.assertIn(("url", "https://bad.example/a"), values)
        self.assertIn(("ip", "8.8.8.8"), values)
        self.assertIn(("domain", "standalone.example.org"), values)
        self.assertNotIn(("domain", "bad.example"), values)
        self.assertNotIn(("domain", "console.log"), values)
        self.assertNotIn(("domain", "node.js"), values)
        self.assertNotIn(("ip", "999.1.1.1"), values)

    def test_merge_iocs_preserves_source_provenance(self) -> None:
        original = (IOC("domain", "bad.example", ("original",)),)
        transformed = (IOC("domain", "bad.example", ("deobfuscated",)),)
        merged = merge_iocs(original, transformed)
        self.assertEqual(merged[0].sources, ("deobfuscated", "original"))


if __name__ == "__main__":
    unittest.main()
