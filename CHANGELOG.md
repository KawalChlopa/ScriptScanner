# Changelog

Wszystkie istotne zmiany projektu są dokumentowane w tym pliku.

## 0.1.0 - 2026-11-15

### Dodano

- lokalny CLI dla PowerShell, JavaScript i Bash,
- identyfikację języka i trzy skróty kryptograficzne,
- wbudowane reguły podejrzanych konstrukcji,
- detekcję obfuskacji i pasywną defuskację,
- ekstrakcję IOC i korelację z logami,
- UTC, opcjonalny NTP, VirusTotal i URLhaus,
- szczegółowy raport terminalowy i wersjonowane pliki JSON/PDF,
- 71 testów jednostkowych i integracyjnych,
- dokumentację architektury, infrastruktury, bezpieczeństwa i pokrycia wymagań,
- zasady utrzymania projektu w `AGENTS.md`,
- monitor aktualnych połączeń TCP/UDP dla Windows i Linux z PID, nazwą procesu,
  terminalem i atomowym raportem JSONL,
- obowiązkowe rozbrajanie URL, domen, IPv4 i IPv6 w terminalu, JSON, PDF, JSONL
  oraz `deobfuscated.txt`, z zachowaniem korelacji rozbrojonych logów.

### Przykłady

- bezpieczne próbki PowerShell, JavaScript i Bash z Base64, sekwencjami hex i
  konkatenacją,
- osobne historie połączeń z dwoma trafieniami i wpisem kontrolnym,
- czytelne nazwy katalogów wynikowych zawierające nazwę, czas UTC i krótki hash,
- test integracyjny utrzymujący próbki i korelację w zgodności z analizatorem.

### Zmieniono

- domyślny katalog wyników z `output` na `report`,
- dodano tryby `files`, `terminal` i `both`,
- usunięto generowanie HTML zgodnie z decyzją użytkownika,
- raport terminalowy sanitizuje niezaufane znaki sterujące,
- utwardzono `.gitignore`: raporty i sekrety pozostają lokalne, a logi z
  `examples/` są jawnie dołączane jako dane demonstracyjne,
- spłaszczono kod produkcyjny bezpośrednio do `src/`, zachowując komendy
  `python src/main.py` oraz `infa-sled`,
- zastąpiono techniczny plik `infa_sled.py` czytelnym punktem startowym
  `main.py`,
- dodano punkt wejścia `infa-sled-monitor` oraz zależność `psutil` do
  przenośnego, tylko do odczytu dostępu do tabel gniazd.
