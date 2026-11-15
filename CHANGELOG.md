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
- 50 testów jednostkowych i integracyjnych,
- dokumentację architektury, infrastruktury, bezpieczeństwa i pokrycia wymagań,
- zasady utrzymania projektu w `AGENTS.md`.

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
- raport terminalowy sanitizuje niezaufane znaki sterujące.
- utwardzono `.gitignore`: raporty i sekrety pozostają lokalne, a logi z
  `examples/` są jawnie dołączane jako dane demonstracyjne.
