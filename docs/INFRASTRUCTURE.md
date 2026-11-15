# Infrastruktura i inwentarz

Dokument jest źródłem prawdy o środowisku wykonawczym, zależnościach, pamięci
trwałej, integracjach oraz CI. Każda zmiana infrastrukturalna wymaga jego
aktualizacji razem z `docs/infrastructure-inventory.json`.

## Środowiska

| Warstwa | Stan | Szczegóły |
|---|---|---|
| Runtime | wymagany | CPython 3.11+ na Windows/Linux/macOS |
| Biblioteki runtime | brak zewnętrznych | wyłącznie biblioteka standardowa |
| CLI | lokalny proces | `infa-sled` lub `python src/main.py` |
| Baza danych | brak | wynik jest wersjonowanymi plikami |
| Kontener | brak | nie jest potrzebny do prototypu |
| Kolejka/cache | brak | analiza synchroniczna, jeden plik na wywołanie |
| Internet | opcjonalny | tylko NTP i wybrany dostawca reputacji |
| CI | GitHub Actions | macierz Python 3.11/3.12, Ubuntu/Windows |

Moduły aplikacji leżą bezpośrednio w `src/`. `main.py` jest głównym punktem
uruchomienia analizatora, a wpis konsolowy `infa-sled` wskazuje na `main:main`.
Projekt nie używa zagnieżdżonego katalogu pakietu.

## Zależności

### Produkcyjne

Brak pakietów PyPI wymaganych w runtime. Generator PDF jest małym,
deterministycznym generatorem PDF 1.4 używającym wbudowanej Helvetica; polskie
znaki są transliterowane tylko w PDF. JSON i raport terminalowy zachowują pełny
UTF-8.

Opcjonalny `--system-history` używa narzędzi lokalnych: Windows `wevtutil qe`
(Sysmon 1/3/22, Security 4688/5156/5157), Linux `journalctl` i odczyt bieżącego
`/var/log/audit/audit.log`. Bez dodatkowych pakietów, usług ani instalacji.
Adaptery opisano w `CONNECTION_CORRELATION.md` i ADR-0004.
Wywołania mają `shell=False`, timeout 10 s, limit stdout 10 MB i stderr 64 KB.
Wyjście jest buforowane w prywatnych plikach tymczasowych i usuwane po odczycie.
Limity są kontrolowane w trakcie działania i po zakończeniu; chwilowe
przekroczenie między kontrolami jest możliwe. Domyślnie odczytujemy ostatnie
24 h i do 1000 wpisów na dziennik. Limit audit.log dotyczy rozpoznanych zdarzeń.

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

Klucz jest czytany domyślnie z `INFA_SLED_API_KEY`; `--api-key-env` pozwala
zmienić nazwę zmiennej. Klucz nie jest zapisywany w raporcie ani logowany.

## Dane i retencja

### Wejście

- jeden plik skryptu, domyślnie do 5 000 000 bajtów,
- zero lub więcej logów UTF-8/UTF-16 z BOM, każdy do 10 000 000 bajtów
  i 100 000 linii (XML Windows, JSONL/CSV, tekst, Linux Audit),
- opcjonalnie jawny odczyt lokalnej historii i oryginalna ścieżka skryptu,
- opcjonalne wartości konfiguracyjne i sekret w środowisku.

### Pamięć

Prototyp przetwarza jeden plik i logi w pamięci procesu. Ograniczenia rozmiaru
są mechanizmem odporności, nie izolacją systemową.

### Wyjście

Katalog `raport/<nazwa>-<język>__<czytelny-czas-UTC>__sha256-<sha8>/` zawiera
pliki `raport.json`, `raport.pdf` i ewentualną kopię po defuskacji. Aplikacja nie usuwa wersji
automatycznie. Operator odpowiada za retencję i uprawnienia katalogu. Zapis
raportu jest atomowy w obrębie systemu plików (`tempfile` + `os.replace`).

CLI domyślnie pokazuje postęp i wynik w terminalu bez zapisu. `--mode raport`
dodaje wersjonowane pliki, a `--type json|pdf|all` wybiera ich format; domyślny
typ `all` oznacza JSON i PDF.

Wszystkie raporty terminalowe i plikowe rozbrajają URL, domeny oraz adresy IP.
Parser logów rozpoznaje zapis `hxxp(s)`, `[.]` i `[:]` bez zapisywania ponownie
uzbrojonych wartości. Dla każdego IOC raport zapisuje rodzaj dowodu, status,
liczbę sprawdzonych źródeł i dopasowań. `execution_check` opisuje dowody
wywołania, a `history_sources` dostępność i pokrycie danych. Schemat wyniku: 1.2.

## Kody wyjścia i obserwowalność

- `0` - analiza i zapis zakończone,
- `2` - kontrolowany błąd wejścia, konfiguracji lub raportu,
- nie ma telemetrii ani zdalnego logowania,
- ostrzeżenia modułów są częścią raportu oraz podsumowania.

## CI

Workflow `.github/workflows/ci.yml` instaluje projekt i uruchamia pełny
`unittest` oraz `compileall` na systemach Windows i Ubuntu dla wspieranych
wersji Pythona. Testy nie otwierają połączeń, nie używają sekretów ani próbek
wykonywalnych.

## Higiena repozytorium

`.gitignore` wyklucza raporty z `raport/` oraz starych `report/` i `output/`, pliki tymczasowe,
cache, środowiska wirtualne, coverage, konfiguracje IDE oraz pliki `.env.*`.
Logi są ignorowane globalnie, ale `examples/**/*.log` są celowo wersjonowane,
ponieważ stanowią dane testowe. Źródłowy `Informatyka_sledcza.pdf` pozostaje
lokalny, ponieważ zawiera dane osobowe autorów i nie jest potrzebny do działania
pakietu.

## Elementy świadomie nieobecne

YARA, Semgrep, ShellCheck, Esprima i PowerShell Parser API widnieją w dokumencie
projektowym jako planowane technologie. Bieżący prototyp nie udaje ich
obecności: nie wywołuje tych silników i nie ma ukrytych zależności.
Jedynymi narzędziami systemowymi są jawne adaptery odczytu historii.
Dodanie adaptera wymaga ADR, kontroli wersji narzędzia, limitu czasu,
testów awarii i aktualizacji niniejszego inwentarza.
