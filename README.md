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
- monitor aktualnych połączeń TCP/UDP z procesami na Windowsie i Linuksie,
- lokalne znaczniki UTC i opcjonalny NTP,
- jawnie opcjonalne zapytania VirusTotal API v3 lub URLhaus,
- szczegółowy raport terminalowy oraz wersjonowane pliki JSON i PDF.
- automatyczne rozbrajanie URL, domen i IP we wszystkich raportach.

## Wymagania

- Python 3.11 lub nowszy,
- `psutil` (instalowany automatycznie razem z projektem) dla monitora systemu,
- sieć nie jest potrzebna do podstawowej analizy.

## Struktura kodu

Kod jest celowo spłaszczony. Wszystkie moduły produkcyjne znajdują się
bezpośrednio w `src/`; nie ma dodatkowego katalogu pakietu:

```text
src/
├── main.py        # główny punkt uruchomienia analizatora
├── system_monitor.py
├── pipeline.py
├── reporting.py
├── rules.py
└── ...
```

## Szybki start

Instalacja:

```powershell
python -m pip install .
infa-sled .\examples\benign.js
```

Uruchomienie bez instalacji:

```powershell
python .\src\main.py .\examples\benign.js
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
python src\main.py examples\benign.js --mode files
python src\main.py examples\benign.js --mode terminal
python src\main.py examples\benign.js --mode both
```

- `files` - zapisuje JSON/PDF, a w terminalu pokazuje tylko podsumowanie i ścieżki,
- `terminal` - pokazuje pełny raport, ale nie tworzy plików,
- `both` - wykonuje oba działania; jest trybem domyślnym.

## Monitor połączeń Windows/Linux

Po instalacji można obserwować aktualne połączenia całego systemu:

```powershell
infa-sled-monitor --duration 30 --interval 1 --mode both
```

Bez instalacji wpisu konsolowego:

```powershell
python .\src\system_monitor.py --duration 30 --interval 1 --mode both
```

Monitor pokazuje nowe połączenia TCP/UDP w terminalu i zapisuje je do czytelnego
katalogu, na przykład:

```text
report/
└── system-connections__2026-11-15_14-30-00-123_UTC__windows/
    └── connections.jsonl
```

Każdy rekord zawiera czas UTC, protokół, lokalny i zdalny adres, stan, PID,
nazwę procesu oraz jego ścieżkę, o ile system pozwala je odczytać. Porty
nasłuchujące i UDP bez zdalnego adresu można dołączyć flagą
`--include-unconnected`. Na Windowsie warto uruchomić terminal jako
administrator, a na Linuksie jako root, jeśli potrzebny jest możliwie pełny
widok procesów.

Wszystkie obserwable w terminalu i plikach są rozbrojone, na przykład
`hxxps://bad[.]example/a`, `192[.]0[.]2[.]10` i `bad[.]example`. Dotyczy to
JSON, PDF, JSONL i `deobfuscated.txt`. Parser logów rozpoznaje taką postać i
normalizuje ją wyłącznie wewnętrznie na potrzeby korelacji.

Zebrany plik jest bezpośrednim wejściem dla korelacji:

```powershell
infa-sled .\examples\suspicious_obfuscated.ps1 `
  --connection-log .\report\system-connections__...__windows\connections.jsonl
```

Monitor działa od chwili uruchomienia i wykonuje migawki. Nie jest snifferem
pakietów: bardzo krótkie połączenie pomiędzy próbkami może zostać pominięte.
Nie odtwarza też automatycznie zdarzeń sprzed startu. Sposoby badania istniejącej
historii opisuje [docs/SYSTEM_MONITORING.md](docs/SYSTEM_MONITORING.md).

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
python src\main.py examples\suspicious_obfuscated.ps1 --connection-log examples\connection_history.log --mode both
python src\main.py examples\suspicious_obfuscated.js --connection-log examples\connection_history_javascript.log --mode both
python src\main.py examples\suspicious_obfuscated.sh --connection-log examples\connection_history_bash.log --mode both
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
- Monitor bieżący nie dowodzi, że program nigdy wcześniej nie był uruchomiony;
  ślady historyczne zależą od wcześniej włączonego audytu i retencji logów.
- Prototyp nie odczytuje automatycznie historycznych dzienników Security,
  PowerShell, Sysmon, auditd ani journald.

Architekturę, infrastrukturę, model zagrożeń i pokrycie wymagań opisano w
katalogu `docs/`.
