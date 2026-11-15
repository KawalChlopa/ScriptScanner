"""Wbudowane reguly wykrywania podejrzanych konstrukcji skryptowych."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    title: str
    description: str
    severity: str
    languages: tuple[str, ...]
    pattern: re.Pattern[str]
    tags: tuple[str, ...]


def default_rules() -> tuple[Rule, ...]:
    """Zwraca deterministyczny zestaw regul prototypu."""

    flags = re.IGNORECASE | re.MULTILINE
    return (
        Rule(
            "PS-EXEC-001",
            "Dynamiczne wykonanie PowerShell",
            "Invoke-Expression lub jego alias moze uruchamiac tekst jako kod.",
            "high",
            ("powershell",),
            re.compile(r"\b(?:invoke-expression|iex)\b", flags),
            ("execution", "powershell"),
        ),
        Rule(
            "PS-NET-001",
            "Pobieranie danych przez PowerShell",
            "Skrypt zawiera konstrukcje typowe dla pobierania z sieci.",
            "high",
            ("powershell",),
            re.compile(
                r"\b(?:downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|iwr|irm)\b"
                r"|\bnet\.webclient\b",
                flags,
            ),
            ("network", "powershell"),
        ),
        Rule(
            "PS-OBF-001",
            "Zakodowane polecenie PowerShell",
            "Parametr EncodedCommand jest czesto uzywany do ukrywania polecen.",
            "high",
            ("powershell",),
            re.compile(r"-(?:encodedcommand|enc)\b", flags),
            ("obfuscation", "powershell"),
        ),
        Rule(
            "JS-EXEC-001",
            "Dynamiczne wykonanie JavaScript",
            "eval lub konstruktor Function moze uruchamiac tekst jako kod.",
            "high",
            ("javascript",),
            re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(", flags),
            ("execution", "javascript"),
        ),
        Rule(
            "JS-PROC-001",
            "Uruchamianie procesu z JavaScript",
            "Modul child_process umozliwia tworzenie procesow systemowych.",
            "high",
            ("javascript",),
            re.compile(r"\bchild_process\b|\b(?:exec|execSync|spawn|spawnSync)\s*\(", flags),
            ("execution", "javascript"),
        ),
        Rule(
            "JS-OBF-001",
            "Budowanie tekstu z kodow znakow",
            "String.fromCharCode bywa uzywane do ukrywania lancuchow.",
            "medium",
            ("javascript",),
            re.compile(r"\bString\.fromCharCode\s*\(", flags),
            ("obfuscation", "javascript"),
        ),
        Rule(
            "SH-NET-001",
            "Potok pobrania do powloki",
            "Dane pobierane z sieci sa kierowane do interpretera polecen.",
            "critical",
            ("bash",),
            re.compile(r"\b(?:curl|wget)\b[^\r\n|]{0,240}\|\s*(?:ba|z)?sh\b", flags),
            ("network", "execution", "bash"),
        ),
        Rule(
            "SH-NET-002",
            "Polaczenie przez pseudo-urzadzenie TCP",
            "Uzycie /dev/tcp moze oznaczac bezposrednia komunikacje sieciowa.",
            "high",
            ("bash",),
            re.compile(r"/dev/(?:tcp|udp)/", flags),
            ("network", "bash"),
        ),
        Rule(
            "GEN-PERS-001",
            "Mozliwy mechanizm utrwalania",
            "Wykryto odwolanie do harmonogramu, autostartu albo crona.",
            "medium",
            ("powershell", "javascript", "bash"),
            re.compile(r"\b(?:schtasks|register-scheduledtask|crontab)\b|currentversion[\\/]run\b", flags),
            ("persistence",),
        ),
        Rule(
            "GEN-CRED-001",
            "Mozliwy dostep do danych uwierzytelniajacych",
            "Wykryto nazwe narzedzia lub magazynu powiazanego z poswiadczeniami.",
            "high",
            ("powershell", "javascript", "bash"),
            re.compile(r"\b(?:mimikatz|lsass|credentialmanager|login\.keychain)\b", flags),
            ("credential-access",),
        ),
    )


def line_number(text: str, offset: int) -> int:
    """Przelicza indeks znaku na numer linii liczony od jednego."""

    return text.count("\n", 0, max(0, offset)) + 1


def excerpt_for(text: str, start: int, end: int, limit: int = 180) -> str:
    """Buduje jednowierszowy, ograniczony fragment dowodu detekcji."""

    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    excerpt = " ".join(text[line_start:line_end].strip().split())
    return excerpt if len(excerpt) <= limit else excerpt[: limit - 3] + "..."


def scan_suspicious(
    text: str,
    language: str,
    rules: tuple[Rule, ...] | None = None,
) -> tuple[Finding, ...]:
    """Dopasowuje reguly bez interpretowania lub wykonywania badanego kodu."""

    active_rules = rules if rules is not None else default_rules()
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for rule in active_rules:
        if language not in rule.languages:
            continue
        for match in rule.pattern.finditer(text):
            match_line = line_number(text, match.start())
            key = (rule.rule_id, match_line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    description=rule.description,
                    line=match_line,
                    excerpt=excerpt_for(text, match.start(), match.end()),
                    tags=rule.tags,
                )
            )
    return tuple(sorted(findings, key=lambda item: (item.line, item.rule_id)))
