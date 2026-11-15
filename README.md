# Infa-Sled

Lokalny prototyp do pasywnej analizy potencjalnie szkodliwych skryptów
PowerShell, JavaScript i Bash. Program traktuje wejście wyłącznie jako dane:
nie uruchamia skryptu, nie importuje go i nie przekazuje jego treści do powłoki.

Projekt realizuje wymagania z dokumentu `Informatyka_sledcza.pdf` i obejmuje:

- rozpoznawanie języka po rozszerzeniu, shebangu i cechach treści,
- SHA-256, SHA-1 i MD5 niezmienionego pliku źródłowego,
- reguły podejrzanych konstrukcji dla trzech języków,
- detekcję Base64, sekwencji `\xNN` / `\uNNNN`, konkatenacji i długich linii,
- pasywną defuskację obsługiwanych literałów,
- ekstrakcję i normalizację URL, domen oraz adresów IPv4,
- korelację IOC z dostarczonymi tekstowymi logami połączeń,
- lokalne znaczniki UTC i opcjonalny NTP,
- jawnie opcjonalne zapytania VirusTotal API v3 lub URLhaus,
- szczegółowy raport terminalowy oraz wersjonowane pliki JSON i PDF.

## Wymagania

- Python 3.11 lub nowszy,
- brak obowiązkowych zależności zewnętrznych,
- sieć nie jest potrzebna do podstawowej analizy.

## Szybki start

Instalacja w trybie edytowalnym:

```powershell
python -m pip install -e .
infa-sled .\examples\benign.js
```

Uruchomienie bez instalacji w PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m infa_sled .\examples\benign.js
```

Domyślny tryb `both` wypisuje szczegółowy raport w terminalu oraz zapisuje
pliki. Każda analiza trafia do osobnej wersji w katalogu `report`:

```text
report/
└── benign-javascript__2026-11-15_14-30-00-123_UTC__sha256-82c35902/
    ├── report.json
    ├── report.pdf
    └── deobfuscated.txt  # tylko gdy wykonano przekształcenia
```

Sposób prezentacji można wybrać jawnie:

```cmd
set "PYTHONPATH=src" && python -m infa_sled examples\benign.js --mode files
set "PYTHONPATH=src" && python -m infa_sled examples\benign.js --mode terminal
set "PYTHONPATH=src" && python -m infa_sled examples\benign.js --mode both
```

- `files` - zapisuje JSON/PDF, a w terminalu pokazuje tylko podsumowanie i ścieżki,
- `terminal` - pokazuje pełny raport, ale nie tworzy plików,
- `both` - wykonuje oba działania; jest trybem domyślnym.

## Korelacja z logiem

Log może być tekstem, CSV albo JSONL zakodowanym jako UTF-8. Analizator
wydobywa z każdego wiersza IOC oraz znacznik czasu ISO 8601, jeżeli występuje.
Nie łączy się z adresem znalezionym w logu.

```powershell
infa-sled .\sample.ps1 --connection-log .\dns.log --connection-log .\proxy.csv
```

Domyślne limity to 5 MB dla skryptu, 10 MB i 100 000 wierszy dla jednego logu.

## Funkcje sieciowe

Funkcje sieciowe są zablokowane, dopóki nie zostanie podana jawna flaga.
Klucz API jest pobierany ze zmiennej środowiskowej, a nie z argumentu procesu.

```powershell
$env:INFA_SLED_API_KEY = "..."
infa-sled .\sample.js `
  --enable-network `
  --ntp-server time.example.org `
  --reputation virustotal
```

Alternatywnie użyj `--reputation urlhaus`. Do dostawcy trafiają wyłącznie
wykryte IOC, nigdy plik lub pełna treść skryptu. Zapytanie IOC może jednak
ujawnić dostawcy dane wrażliwe; szczegóły opisuje `docs/SECURITY.md`.

## Najważniejsze opcje CLI

```text
--mode files|terminal|both
--formats json,pdf
--output PATH                  (domyślnie: report)
--max-file-size BYTES
--connection-log PATH          (można powtórzyć)
--enable-network
--ntp-server HOST
--reputation virustotal|urlhaus
--api-key-env NAZWA_ZMIENNEJ
--timeout SEKUNDY
```

Pełna pomoc: `infa-sled --help`.

## Demonstracja obfuskacji i historii połączeń

Repozytorium zawiera bezpieczne próbki tekstowe PowerShell, JavaScript i Bash z
Base64, sekwencjami hex, konkatenacją oraz podejrzanymi nazwami. Nie uruchamiaj
ich jako skryptów - podawaj je wyłącznie analizatorowi z właściwym logiem:

```cmd
set "PYTHONPATH=src" && python -m infa_sled examples\suspicious_obfuscated.ps1 --connection-log examples\connection_history.log --mode both
set "PYTHONPATH=src" && python -m infa_sled examples\suspicious_obfuscated.js --connection-log examples\connection_history_javascript.log --mode both
set "PYTHONPATH=src" && python -m infa_sled examples\suspicious_obfuscated.sh --connection-log examples\connection_history_bash.log --mode both
```

Oczekiwany rezultat obejmuje detekcje podejrzanych konstrukcji, trzy sygnały
obfuskacji, IOC z oryginalnej i przekształconej treści oraz dwie korelacje z
logiem. Trzeci adres w logu jest wpisem kontrolnym i nie powinien zostać
dopasowany.

## Testy

```powershell
python -m unittest discover -s tests -t . -v
python -m compileall -q src tests
```

Każda funkcja produkcyjna ma test bezpośredni lub test przepływu, a krytyczne
granice wejścia mają przypadki błędne. Szczegółowa mapa znajduje się w
`docs/TESTING.md`.

## Ograniczenia prototypu

- To narzędzie wspomagające analizę, nie antywirus i nie sandbox dynamiczny.
- Brak detekcji nie oznacza, że skrypt jest bezpieczny.
- Wbudowana analiza używa deterministycznych reguł Regex i lekkiej analizy
  struktury tekstu. Adaptery YARA, Semgrep, ShellCheck, Esprima i PowerShell
  Parser API są zaplanowanym rozszerzeniem, nie ukrytą zależnością.
- Defuskacja celowo obsługuje ograniczone, jednoznaczne transformacje i nigdy
  nie interpretuje uzyskanego kodu.
- Korelacja działa na jawnie podanych logach; prototyp nie odczytuje samodzielnie
  uprzywilejowanych dzienników systemowych.

Architekturę, infrastrukturę, model zagrożeń i pokrycie wymagań opisano w
katalogu `docs/`.
