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
- sprawdzenie IOC z rozróżnieniem połączenia, żądania URL, DNS, zezwolenia,
  blokady i samej wzmianki w logu,
- dowody wywołania skryptu według pełnej ścieżki albo SHA-256 skryptu,
- opcjonalny, jednorazowy odczyt dostępnej historii Windows/Linux,
- lokalne znaczniki UTC i opcjonalny NTP,
- jawnie opcjonalne zapytania VirusTotal API v3 lub URLhaus,
- szczegółowy raport terminalowy oraz wersjonowane pliki JSON i PDF,
- automatyczne rozbrajanie URL, domen i IP we wszystkich raportach.

## Wymagania

- Python 3.11 lub nowszy,
- brak obowiązkowych zależności zewnętrznych,
- sieć nie jest potrzebna do podstawowej analizy.

## Struktura kodu

Kod jest celowo spłaszczony. Wszystkie moduły produkcyjne znajdują się
bezpośrednio w `src/`; nie ma dodatkowego katalogu pakietu:

```text
src/
├── main.py        # główny punkt uruchomienia analizatora
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

Domyślnie program pokazuje wynik i rzeczywisty postęp analizy w terminalu, bez
tworzenia plików. Zapis włącza się jawnie przez `--mode raport`. Każdy zapis
trafia do osobnej wersji w katalogu `raport`:

```text
raport/
└── benign-javascript__2026-11-15_14-30-00-123_UTC__sha256-82c35902/
    ├── raport.json
    ├── raport.pdf
    └── deobfuscated.txt  # tylko gdy wykonano przekształcenia
```

Przykłady trybów:

```cmd
python src\main.py examples\benign.js
python src\main.py examples\benign.js --mode raport
python src\main.py examples\benign.js --mode raport --type pdf
python src\main.py examples\benign.js --mode raport --type json
```

- bez `--mode` - terminal, bez zapisu plików,
- `--mode raport` - terminal oraz JSON i PDF,
- `--mode raport --type pdf` - terminal oraz PDF,
- `--mode raport --type json` - terminal oraz JSON,
- `--type all` - jawny odpowiednik domyślnego zestawu JSON i PDF w trybie raportu.

Opcja `--type` jest poprawna wyłącznie razem z `--mode raport`.

## Korelacja z logiem

Log może być tekstem, CSV, JSONL, XML zdarzeń Windows albo surowym logiem
Linux Audit. Pliki obsługują UTF-8 oraz UTF-16 z BOM. Analizator nie łączy się
z adresem znalezionym w logu.

```powershell
infa-sled .\sample.ps1 --connection-log .\dns.log --connection-log .\proxy.csv
```

Domyślne limity to 5 MB dla skryptu, 10 MB i 100 000 wierszy dla jednego logu.

Raport oddziela zdarzenie połączenia (`TAK`), żądanie URL, blokadę, zezwolenie,
DNS oraz samą wzmiankę. Dopasowanie hosta adresu URL jest oznaczone jako
`TYLKO HOST URL`, nigdy jako potwierdzenie użycia całego URL.
`NIE WYKRYTO` oznacza brak dowodu w rozpoznanych zdarzeniach danego rodzaju.
`NIE SPRAWDZONO` oznacza brak odpowiednich danych, np. niedostępny lub pusty
dziennik, wyłączony audyt albo sam tekst bez zdarzeń sieciowych.
Brak dowodu nie oznacza, że zdarzenia nigdy nie było.

## Historia własnego komputera i uruchomienia skryptu

```cmd
python src\main.py examples\benign.js --system-history --mode raport
python src\main.py examples\benign.js --system-history --history-hours 168 --history-max-events 5000 --mode raport
```

Windows: odczyt Sysmon (1, 3, 22) i Security (4688, 5156, 5157) przez
`wevtutil`. Linux: `journalctl` oraz bieżący `/var/log/audit/audit.log`.
Odczyt dotyczy domyślnie ostatnich 24 godzin i maksymalnie 1000 wpisów na
dziennik; raport podaje zakres oraz ograniczenia. Logowanie musiało być
włączone wcześniej. Niektóre źródła wymagają administratora/roota; brak dostępu
jest odnotowany bez przerywania analizy. Program nie włącza audytu.

Dowody uruchomienia można też dostarczyć jako plik:

```cmd
python src\main.py sample.ps1 --execution-log zdarzenia.xml --mode raport
```

Potwierdzenie wywołania wymaga zdarzenia utworzenia procesu i dokładnej ścieżki
argumentu skryptu (z katalogiem roboczym dla ścieżek względnych) albo jawnego
SHA-256 **skryptu** w obsługiwanym formacie JSONL. Sama nazwa, historia powłoki,
zdarzenie PowerShell 4104 i hash interpretera nie wystarczają. Dowód wywołania
nie dowodzi ukończenia skryptu; sama ścieżka nie potwierdza jego dawnej treści.

Przeniesiony plik może mieć inną ścieżkę niż w logach. Do takiej analizy służy
`--original-script-path`. Bezpieczna demonstracja na syntetycznych dowodach:

```cmd
python src\main.py examples\suspicious_obfuscated.ps1 --connection-log examples\history_demo.jsonl --original-script-path C:\demo\suspicious_obfuscated.ps1 --mode raport
```

Ten przykład pokazuje wywołanie skryptu, połączenie do IP i zablokowaną próbę
do URL. To dane demonstracyjne, nie historia Twojego komputera. Powiązanie
sieci z wywołaniem skryptu wymaga zgodnego hosta i `ProcessGuid`; sam PID lub
wspólny adres nie są podstawą takiego przypisania.

Dokładne znaczenie statusów opisuje
[docs/CONNECTION_CORRELATION.md](docs/CONNECTION_CORRELATION.md).

Wszystkie obserwable w terminalu i plikach są rozbrojone, na przykład
`hxxps://bad[.]example/a`, `192[.]0[.]2[.]10` i `bad[.]example`. Parser logów
rozpoznaje taką postać wyłącznie wewnętrznie na potrzeby porównania.

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
--mode terminal|raport         (domyślnie: terminal)
--type json|pdf|all            (tylko z --mode raport)
--output PATH                  (domyślnie: raport)
--max-file-size BYTES
--connection-log PATH          (można powtórzyć)
--execution-log PATH           (można powtórzyć)
--system-history               (jednorazowy odczyt Windows/Linux)
--history-hours N              (domyślnie 24; zakres 1–8760)
--history-max-events N         (domyślnie 1000; zakres 1–10000)
--original-script-path PATH    (pełna ścieżka skryptu na maszynie z logów)
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
python src\main.py examples\suspicious_obfuscated.ps1 --connection-log examples\connection_history.log --mode raport
python src\main.py examples\suspicious_obfuscated.js --connection-log examples\connection_history_javascript.log --mode raport
python src\main.py examples\suspicious_obfuscated.sh --connection-log examples\connection_history_bash.log --mode raport
```

Oczekiwany rezultat obejmuje detekcje podejrzanych konstrukcji, trzy sygnały
obfuskacji, IOC z oryginalnej i przekształconej treści oraz dokładne i hostowe
dopasowania do logu. Blokady są prezentowane jako zablokowane próby, a zezwolenia jako
dozwolone próby. Dowód dotyczący IP hosta URL nie potwierdza samego URL.
Trzeci adres w logu jest wpisem kontrolnym i nie powinien zostać dopasowany.

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
- Odczyt systemu wymaga `--system-history`. Nie odtwarza usuniętych logów,
  nie odzyskuje zdarzeń sprzed włączenia audytu i nie gwarantuje pełnej historii.
- Linux: obsługiwane są wychodzące wpisy UFW, Audit EXECVE (x86-64, i386,
  aarch64) oraz XML Sysmon w `MESSAGE` dziennika. Samo journald nie zapewnia
  rejestracji wszystkich połączeń ani wszystkich uruchomień.

Architekturę, infrastrukturę, model zagrożeń i pokrycie wymagań opisano w
katalogu `docs/`.
