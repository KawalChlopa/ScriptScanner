# Infrastruktura i inwentarz

Dokument jest źródłem prawdy o środowisku wykonawczym, zależnościach, pamięci
trwałej, integracjach oraz CI. Każda zmiana infrastrukturalna wymaga jego
aktualizacji razem z `docs/infrastructure-inventory.json`.

## Środowiska

| Warstwa | Stan | Szczegóły |
|---|---|---|
| Runtime | wymagany | CPython 3.11+ na Windows/Linux/macOS |
| Biblioteki runtime | brak zewnętrznych | wyłącznie biblioteka standardowa |
| CLI | lokalny proces | `infa-sled` albo `python -m infa_sled` |
| Baza danych | brak | wynik jest wersjonowanymi plikami |
| Kontener | brak | nie jest potrzebny do prototypu |
| Kolejka/cache | brak | analiza synchroniczna, jeden plik na wywołanie |
| Internet | opcjonalny | tylko NTP i wybrany dostawca reputacji |
| CI | GitHub Actions | macierz Python 3.11/3.12, Ubuntu/Windows |

## Zależności

### Produkcyjne

Brak pakietów PyPI. `pyproject.toml` deklaruje pustą listę `dependencies`.
Generator PDF jest małym, deterministycznym generatorem PDF 1.4 używającym
wbudowanej Helvetica; polskie znaki są transliterowane tylko w PDF. JSON i
raport terminalowy zachowują pełny UTF-8.

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

## Kody wyjścia i obserwowalność

- `0` - analiza i zapis zakończone,
- `2` - kontrolowany błąd wejścia, konfiguracji lub raportu,
- nie ma telemetrii ani zdalnego logowania,
- ostrzeżenia modułów są częścią raportu oraz podsumowania.

## CI

Workflow `.github/workflows/ci.yml` uruchamia pełny `unittest` i `compileall` na
systemach Windows i Ubuntu dla wspieranych wersji Pythona. Nie używa sekretów,
sieciowych funkcji aplikacji ani próbek wykonywalnych.

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
