from __future__ import annotations

import unittest

from sanitization import (
    defang_data,
    defang_ip,
    defang_observable,
    defang_text,
    defang_url,
    restore_defanged_text,
)


class SanitizationTests(unittest.TestCase):
    def test_defang_ip_handles_ipv4_ipv6_and_invalid_text(self) -> None:
        self.assertEqual(defang_ip("192.0.2.10"), "192[.]0[.]2[.]10")
        self.assertEqual(defang_ip("2001:db8::1"), "2001[:]db8[:][:]1")
        self.assertEqual(defang_ip("999.1.1.1"), "999.1.1.1")

    def test_defang_url_disarms_scheme_host_and_preserves_path(self) -> None:
        self.assertEqual(
            defang_url("https://bad.example:443/a?q=1"),
            "hxxps://bad[.]example:443/a?q=1",
        )
        self.assertEqual(defang_url("ftp://bad.example/a"), "ftp://bad.example/a")

    def test_defang_text_is_idempotent_and_does_not_change_filename(self) -> None:
        source = "https://bad.example/a 192.0.2.10 sample.ps1"
        expected = "hxxps://bad[.]example/a 192[.]0[.]2[.]10 sample.ps1"
        self.assertEqual(defang_text(source), expected)
        self.assertEqual(defang_text(expected), expected)

    def test_defang_observable_handles_bare_domain_and_unknown_kind(self) -> None:
        self.assertEqual(defang_observable("domain", "bad.example"), "bad[.]example")
        self.assertEqual(
            defang_observable("url", "http://bad.example"), "hxxp://bad[.]example"
        )

    def test_defang_data_recurses_without_changing_non_strings(self) -> None:
        value = {"items": ["8.8.8.8", {"url": "https://bad.example"}], "count": 2}
        result = defang_data(value)
        self.assertEqual(result["items"][0], "8[.]8[.]8[.]8")
        self.assertEqual(result["items"][1]["url"], "hxxps://bad[.]example")
        self.assertEqual(result["count"], 2)

    def test_restore_defanged_text_supports_generated_and_common_forms(self) -> None:
        restored = restore_defanged_text(
            "hxxps://bad[.]example/a 192[.]0[.]2[.]10 and other(.)example"
        )
        self.assertEqual(
            restored,
            "https://bad.example/a 192.0.2.10 and other.example",
        )


if __name__ == "__main__":
    unittest.main()
