# Macierz śledzenia wymagań

Źródłem wymagań jest `Informatyka_sledcza.pdf`. Status odnosi się do prototypu
w tym repozytorium.

## Funkcjonalne

| ID | Wymaganie | Implementacja | Test | Status |
|---|---|---|---|---|
| F-01 | odczyt PowerShell/JavaScript/Bash | `fileio.read_script`, `detect_language` | `FileIoTests` | pełne |
| F-02 | rozpoznanie języka z cech pliku i treści | rozszerzenie, shebang, heurystyki | `test_detect_language_*` | pełne dla 3 języków |
| F-03 | SHA-256, SHA-1, MD5 | `compute_hashes` | `test_compute_hashes_*` | pełne |
| F-04 | podejrzane instrukcje i wzorce | `rules.py`, Regex, reguły językowe | `RulesTests`, pipeline | częściowe: bez pełnego AST/YARA |
| F-05 | rozpoznanie obfuskacji | Base64, escapes, konkatenacja, długa linia | `ObfuscationTests` | pełne dla zadeklarowanego zakresu |
| F-06 | pasywna defuskacja | Base64, `\x`, `\u`, proste literały | `test_deobfuscate_*` | pełne dla zadeklarowanego zakresu |
| F-07 | IP, domeny i URL z obu reprezentacji | `ioc.py`, `pipeline.py` | `IocTests`, pipeline | pełne |
| F-08 | niezależny zapis wyników i przekształceń | wersjonowane raporty, `deobfuscated.txt` | `ReportingTests`, pipeline | pełne |
| F-09 | raport wzorców, defuskacji i IOC | terminal, JSON i PDF | `ReportingTests` | zmienione decyzją użytkownika: HTML usunięty |
| F-10 | błędy wejścia i ograniczenia | wyjątki domenowe, ostrzeżenia, kod 2 | testy granic i CLI | pełne |

## Moduły rozszerzone z projektu systemu

| ID | Wymaganie | Implementacja | Status |
|---|---|---|---|
| M-08 | znaczniki start/koniec, opcjonalny NTP | `timing.py`, oznaczony fallback | pełne |
| M-09 | historia połączeń | jawnie dostarczone logi, dokładna korelacja IOC | pełne dla prototypu lokalnego |
| R-01 | opcjonalna reputacja IOC | VirusTotal v3 i URLhaus, bramka sieciowa | pełne, wymaga klucza |

## Niefunkcjonalne

| ID | Wymaganie | Dowód | Status |
|---|---|---|---|
| NF-01 | brak wykonania kodu | architektura bez subprocess/eval, `AGENTS.md` | pełne |
| NF-02 | integralność źródła | odczyt binarny, skróty, osobny katalog raportów, test integralności | pełne |
| NF-03 | modularność | 12 modułów z typowanymi modelami | pełne |
| NF-04 | rozszerzalność | stabilne reguły i kontrakty modeli | pełne dla reguł |
| NF-05 | powtarzalność | deterministyczne lokalne etapy; czas i API jawnie zmienne | pełne lokalnie |
| NF-06 | odporność i limity | rozmiar, linie, odpowiedź API, timeout sieci | pełne; brak limitu CPU Regex |
| NF-07 | praca lokalna | zero obowiązkowych zależności i usług | pełne |

## Planowane rozszerzenia, nie kryteria ukończenia prototypu

1. Adapter YARA z osobnym pakietem reguł.
2. Adaptery Semgrep i ShellCheck z `shell=False` i timeoutem.
3. Pełne parsery AST dla JavaScript i PowerShell.
4. Obsługa uprzywilejowanych dzienników systemowych przez jawne adaptery OS.
5. Limit czasu/CPU dla kosztownych reguł w osobnym procesie izolowanym.
