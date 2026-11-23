# Macierz śledzenia wymagań

Źródłem wymagań jest `Informatyka_sledcza.pdf`. Status odnosi się do prototypu
w tym repozytorium.

## Funkcjonalne

| ID | Wymaganie | Implementacja | Test | Status |
|---|---|---|---|---|
| F-01 | odczyt PowerShell/JavaScript/Bash | `fileio.read_script`, `detect_language` | `FileIoTests` | pełne |
| F-02 | rozpoznanie języka z cech pliku i treści | rozszerzenie, shebang, heurystyki | `test_detect_language_*` | pełne dla 3 języków |
| F-03 | SHA-256, SHA-1, MD5 | `compute_hashes` | `test_compute_hashes_*` | pełne |
| F-04 | podejrzane instrukcje i wzorce | reguły wbudowane, YARA, Semgrep, ShellCheck oraz AST z Esprimy i PowerShell Parser API | `RulesTests`, `EngineAdapterTests`, `InstalledEngineTests` | pełne dla dostępnych silników i reguł |
| F-05 | rozpoznanie obfuskacji | Base64, escapes, konkatenacja, długa linia | `ObfuscationTests` | pełne dla zadeklarowanego zakresu |
| F-06 | pasywna defuskacja | Base64, `\x`, `\u`, proste literały | `test_deobfuscate_*` | pełne dla zadeklarowanego zakresu |
| F-07 | IP, domeny i URL z obu reprezentacji | `ioc.py`, `pipeline.py` | `IocTests`, pipeline | pełne |
| F-08 | niezależny zapis wyników i przekształceń | wersjonowane raporty, `deobfuscated.txt` | `ReportingTests`, pipeline | pełne |
| F-09 | raport wzorców, defuskacji i IOC | terminal, JSON i PDF; wszystkie obserwable rozbrojone | `ReportingTests`, `SanitizationTests` | zmienione decyzją użytkownika: HTML usunięty |
| F-10 | błędy wejścia i ograniczenia | wyjątki domenowe, ostrzeżenia, kod 2 | testy granic i CLI | pełne |

## Moduły rozszerzone z projektu systemu

| ID | Wymaganie | Implementacja | Status |
|---|---|---|---|
| M-08 | znaczniki start/koniec, opcjonalny NTP | `timing.py`, oznaczony fallback | pełne |
| M-09 | historia połączeń | import logów, opcjonalny odczyt OS, rodzaje dowodów, dopasowanie hosta URL | pełne dla obsługiwanych źródeł; wymaga wcześniejszego logowania |
| M-10 | historia wywołania skryptu | Sysmon 1, Security 4688, Linux Audit, JSONL; dokładna ścieżka/hash skryptu | ograniczone do rozpoznanych zdarzeń; nie dowodzi ukończenia |
| M-11 | czytelny interfejs wyników | domyślny terminal, postęp poza raportem, `--mode raport --type ...` | pełne |
| R-01 | opcjonalna reputacja IOC | VirusTotal v3 i URLhaus, bramka sieciowa | pełne, wymaga klucza |

## Niefunkcjonalne

| ID | Wymaganie | Dowód | Status |
|---|---|---|---|
| NF-01 | brak wykonania kodu | stałe adaptery narzędzi odczytu i silników pasywnych, z wejściem jako dane, `AGENTS.md` | pełne |
| NF-02 | integralność źródła | odczyt binarny, skróty, osobny katalog raportów, test integralności | pełne |
| NF-03 | modularność | moduły o rozdzielonych odpowiedzialnościach i typowane modele | pełne |
| NF-04 | rozszerzalność | stabilne reguły i kontrakty modeli | pełne dla reguł |
| NF-05 | powtarzalność | deterministyczne lokalne etapy; czas i API jawnie zmienne | pełne lokalnie |
| NF-06 | odporność i limity | rozmiar, linie, odpowiedź API, timeout sieci i silników, limity wyjścia | pełne dla adapterów; brak limitu CPU Regex |
| NF-07 | praca lokalna | lokalne zależności, brak usług wymaganych podczas analizy | pełne |

## Planowane rozszerzenia, nie kryteria ukończenia prototypu

1. Dalsze formaty historii, rotowane audit.log, bezpośredni import binarnego EVTX,
   rozpoznawanie kolejnych interpreterów i pośrednich łańcuchów uruchomienia.
2. Limit czasu/CPU dla kosztownych reguł Regex w osobnym procesie izolowanym.
