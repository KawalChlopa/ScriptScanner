# Infrastruktura i inwentarz

Dokument jest źródłem prawdy o środowisku wykonawczym, zależnościach, pamięci
trwałej, integracjach oraz CI. Każda zmiana infrastrukturalna wymaga jego
aktualizacji razem z `docs/infrastructure-inventory.json`.

## Środowiska

| Warstwa | Stan | Szczegóły |
|---|---|---|
| Runtime | wymagany | CPython 3.11+; analizator: Windows/Linux/macOS, monitor: Windows/Linux |
| Biblioteki runtime | wymagana | `psutil>=5.9,<8` dla przenośnego odczytu gniazd i procesów |
| CLI | lokalny proces | `infa-sled`, `infa-sled-monitor` lub bezpośrednie pliki z `src/` |
| Baza danych | brak | wynik jest wersjonowanymi plikami |
| Kontener | brak | nie jest potrzebny do prototypu |
| Kolejka/cache | brak | analiza synchroniczna, jeden plik na wywołanie |
| Internet | opcjonalny | tylko NTP i wybrany dostawca reputacji |
| CI | GitHub Actions | macierz Python 3.11/3.12, Ubuntu/Windows |

Moduły aplikacji leżą bezpośrednio w `src/`. `main.py` jest głównym punktem
uruchomienia analizatora, a wpis konsolowy `infa-sled` wskazuje na `main:main`.
`system_monitor.py` jest punktem uruchomienia monitora, a wpis
`infa-sled-monitor` wskazuje na `system_monitor:main`. Projekt nie używa
zagnieżdżonego katalogu pakietu.

## Zależności

### Produkcyjne

- `psutil>=5.9,<8` - przenośny, tylko do odczytu dostęp do systemowych połączeń
  i metadanych procesów na Windowsie oraz Linuksie.

Analiza statyczna nadal używa wyłącznie biblioteki standardowej, lecz zależność
jest instalowana dla wspólnej dystrybucji obu CLI. Uzasadnienie znajduje się w
`docs/decisions/0003-cross-platform-connection-monitor.md`. Generator PDF jest
małym, deterministycznym generatorem PDF 1.4 używającym wbudowanej Helvetica;
polskie znaki są transliterowane tylko w PDF. JSON, JSONL i raport terminalowy
zachowują pełny UTF-8.

### Budowanie i testowanie

- `setuptools>=69` - backend instalacji pakietu,
- `unittest`, `compileall` - dostarczane z Pythonem,
- `ruff` i `coverage` - zalecane lokalne narzędzia jakości, nie są wymagane do
  uruchomienia i nie są instalowane przez aplikację.

## Integracje wychodzące

| Integracja | Protokół/cel | Włączanie | Wysyłane dane | Sekret |
|---|---|---|---|---|
| NTP | UDP/123 do podanego hosta | `--enable-network --ntp-server` | pakiet czasu, bez skryptu | brak |
| VirusTotal API v3 | HTTPS do `www.virustotal.com` | `--enable-network --reputation virustotal` | pojedynczy URL/domena/IP | nagłówek `x-apikey` |
| URLhaus API v1 | HTTPS do `urlhaus-api.abuse.ch` | `--enable-network --reputation urlhaus` | pojedynczy URL albo host | nagłówek `Auth-Key` |

Monitor nie jest integracją wychodzącą: `psutil.net_connections(kind="inet")`
odczytuje lokalne tabele gniazd i nie tworzy żadnego połączenia.

Klucz jest czytany domyślnie z `INFA_SLED_API_KEY`; `--api-key-env` pozwala
zmienić nazwę zmiennej. Klucz nie jest zapisywany w raporcie ani logowany.

## Dane i retencja

### Wejście

- jeden plik skryptu, domyślnie do 5 000 000 bajtów,
- zero lub więcej logów UTF-8, każdy do 10 000 000 bajtów i 100 000 linii,
- opcjonalne wartości konfiguracyjne i sekret w środowisku.

### Pamięć

Prototyp przetwarza jeden plik i logi w pamięci procesu. Ograniczenia rozmiaru
są mechanizmem odporności, nie izolacją systemową.

### Wyjście

Katalog `report/<nazwa>-<język>__<czytelny-czas-UTC>__sha256-<sha8>/` zawiera
raporty i ewentualną kopię po defuskacji. Aplikacja nie usuwa wersji
automatycznie. Operator odpowiada za retencję i uprawnienia katalogu. Zapis
raportu jest atomowy w obrębie systemu plików (`tempfile` + `os.replace`).

CLI udostępnia trzy tryby prezentacji: `files` (JSON/PDF), `terminal` (bez
zapisu) oraz `both` (oba kanały, domyślnie).

Monitor zapisuje
`report/system-connections__<czytelny-czas-UTC>__<system>/connections.jsonl`.
Każda linia jest osobnym rekordem. Limit jednej sesji wynosi 100 000 zdarzeń,
czas najwyżej 86 400 sekund, a interwał 0,1-60 sekund. Katalog `report/` jest
ignorowany przez Git.

Wszystkie raporty terminalowe i plikowe rozbrajają URL, domeny oraz adresy IP.
JSONL monitora pozostaje wejściem korelacji, ponieważ parser rozpoznaje zapis
`hxxp(s)`, `[.]` i `[:]` bez zapisywania ponownie uzbrojonych wartości.

## Kody wyjścia i obserwowalność

- `0` - analiza i zapis zakończone,
- `2` - kontrolowany błąd wejścia, konfiguracji lub raportu,
- `130` - monitor przerwany przez użytkownika,
- nie ma telemetrii ani zdalnego logowania,
- ostrzeżenia modułów są częścią raportu oraz podsumowania.

## CI

Workflow `.github/workflows/ci.yml` instaluje projekt i uruchamia pełny
`unittest` oraz `compileall` na systemach Windows i Ubuntu dla wspieranych
wersji Pythona. Testy monitora używają atrap systemowych; nie otwierają
połączeń, nie używają sekretów ani próbek wykonywalnych.

## Higiena repozytorium

`.gitignore` wyklucza raporty z `report/` i starego `output/`, pliki tymczasowe,
cache, środowiska wirtualne, coverage, konfiguracje IDE oraz pliki `.env.*`.
Logi są ignorowane globalnie, ale `examples/**/*.log` są celowo wersjonowane,
ponieważ stanowią dane testowe. Źródłowy `Informatyka_sledcza.pdf` pozostaje
lokalny, ponieważ zawiera dane osobowe autorów i nie jest potrzebny do działania
pakietu.

## Elementy świadomie nieobecne

YARA, Semgrep, ShellCheck, Esprima i PowerShell Parser API widnieją w dokumencie
projektowym jako planowane technologie. Bieżący prototyp nie udaje ich
obecności: nie wywołuje zewnętrznych plików wykonywalnych i nie ma ukrytych
zależności. Dodanie adaptera wymaga ADR, kontroli wersji narzędzia, limitu czasu,
testów awarii i aktualizacji niniejszego inwentarza.
