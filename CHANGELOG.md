# Changelog

Wszystkie istotne zmiany projektu są dokumentowane w tym pliku.

## Niewydane

- Dodano instalator Windows i próbki do sprawdzenia pięciu silników z CLI.
- Dodano lokalne skanowanie przez YARA, Semgrep, ShellCheck, Esprimę i
  PowerShell Parser API, także dla kopii po defuskacji.
- Raporty pokazują status każdego uruchomionego silnika. JSON 1.3 dodaje
  pole `engine_runs`.
- Dodano opcjonalną instalację `.[static-analysis]` i zadanie CI
  testujące rzeczywiste narzędzia.

## 0.1.0 - 2026-11-15

### Dodano

- jednorazowy odczyt historii Windows/Linux przez `--system-history`,
- dowody wywołania skryptu przez `--execution-log` i `--original-script-path`,
- parsery XML zdarzeń Windows, Linux Audit i kontraktu JSONL/CSV,
- rozróżnienie połączenia, żądania URL, zezwolenia, blokady, DNS i wzmianki,
- korelację zdarzeń z wywołaniem skryptu przez host i ProcessGuid,
- schemat raportu 1.2: `execution_check`, `history_sources`, rodzaje dowodów,
- syntetyczne dowody do demonstracji w `examples/history_demo.jsonl`,
- lokalny CLI dla PowerShell, JavaScript i Bash,
- identyfikację języka i trzy skróty kryptograficzne,
- wbudowane reguły podejrzanych konstrukcji,
- detekcję obfuskacji i pasywną defuskację,
- ekstrakcję IOC i korelację z logami,
- UTC, opcjonalny NTP, VirusTotal i URLhaus,
- szczegółowy raport terminalowy i wersjonowane pliki JSON/PDF,
- testy jednostkowe i integracyjne dla wszystkich funkcji oraz granic wejścia,
- dokumentację architektury, infrastruktury, bezpieczeństwa i pokrycia wymagań,
- zasady utrzymania projektu w `AGENTS.md`,
- obowiązkowe rozbrajanie URL, domen, IPv4 i IPv6 w terminalu, JSON i PDF
  oraz `deobfuscated.txt`, z zachowaniem korelacji rozbrojonych logów.

### Przykłady

- bezpieczne próbki PowerShell, JavaScript i Bash z Base64, sekwencjami hex i
  konkatenacją,
- osobne historie połączeń z dwoma trafieniami i wpisem kontrolnym,
- czytelne nazwy katalogów wynikowych zawierające nazwę, czas UTC i krótki hash,
- test integracyjny utrzymujący próbki i korelację w zgodności z analizatorem.

### Zmieniono

- domyślny katalog wyników z `output`/`report` na `raport`,
- nazwy generowanych plików na `raport.json` i `raport.pdf`,
- ustawiono terminal jako tryb domyślny bez zapisu; `--mode raport` włącza
  pliki, a `--type json|pdf|all` wybiera format,
- przeniesiono etapy analizy z końcowego raportu do komunikatów postępu
  pokazywanych podczas wykonywania kolejnych etapów,
- usunięto generowanie HTML zgodnie z decyzją użytkownika,
- raport terminalowy sanitizuje niezaufane znaki sterujące,
- utwardzono `.gitignore`: raporty i sekrety pozostają lokalne, a logi z
  `examples/` są jawnie dołączane jako dane demonstracyjne,
- spłaszczono kod produkcyjny bezpośrednio do `src/`, zachowując komendy
  `python src/main.py` oraz `infa-sled`,
- zastąpiono techniczny plik `infa_sled.py` czytelnym punktem startowym
  `main.py`,
- raport rozróżnia rodzaje dowodów; sama wzmianka ani zablokowana próba nie
  potwierdza połączenia. Usunięto osobny monitor połączeń.
