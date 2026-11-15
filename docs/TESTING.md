# Strategia testów

## Bramka jakości

Każda nowa albo zmieniona funkcja produkcyjna wymaga testu ścieżki poprawnej
oraz odpowiedniego przypadku brzegowego lub błędu. Obowiązkowe komendy:

```powershell
python -m unittest discover -s tests -t . -v
python -m compileall -q src tests
```

Testy używają katalogu `tmp/test-runtime` wewnątrz repozytorium i nie wykonują
funkcji sieciowych. NTP i HTTPS są zastępowane kontrolowanymi atrapami.

## Mapa pokrycia funkcji

| Moduł produkcyjny | Pokrywane funkcje | Testy |
|---|---|---|
| `config.py` | `AnalysisConfig.__post_init__` | `ConfigTests` |
| `models.py` | `to_primitive` | `ModelsTests` |
| `fileio.py` | skróty, dekodowanie, język, mtime, odczyt | `FileIoTests` |
| `rules.py` | reguły, linie, fragmenty, skanowanie | `RulesTests` |
| `obfuscation.py` | współczynnik, Base64, sygnały, 3 transformacje | `ObfuscationTests` |
| `ioc.py` | normalizacja, ekstrakcja, scalanie | `IocTests` |
| `sanitization.py` | URL, domeny, IPv4/IPv6, struktury i normalizacja wejścia | `SanitizationTests` |
| `connections.py` | czas, odczyt z limitami, dokładne i hostowe dopasowanie, rodzaje dowodów | `ConnectionTests`, `EvidenceTests` |
| `history.py` | XML/providery/kierunek, JSONL/CSV, Audit, ścieżki, argumenty, wykonanie, adaptery OS i limity | `HistoryParsingTests`, `EvidenceTests`, `SystemHistoryTests` |
| `timing.py` | format UTC, system, NTP, fallback | `TimingTests` |
| `reputation.py` | żądania, limit JSON, mapowanie, błędy | `ReputationTests` |
| `reporting.py` | nazwy `raport.json`/`raport.pdf`, wspólna prezentacja dowodów, terminal, JSON/PDF, atomowy zapis | `ReportingTests`, `EvidenceTests` |
| `pipeline.py` | scalanie, analiza, callback postępu, zapis, ostrzeżenia | `PipelineTests` |
| `main.py` | domyślny terminal, `--mode raport`, typy, konfiguracja i kody wyjścia | `CliTests` |

## Kategorie

- testy jednostkowe: deterministyczne reguły i transformacje,
- testy granic: rozmiary, liczba linii, kodowania, niepoprawny JSON/PDF input,
- testy bezpieczeństwa: brak sieci dzięki atrapom, sanitacja terminala i PDF,
- testy rozbrajania: idempotentność oraz brak aktywnych URL/IP w JSON,
  terminalu i danych po defuskacji,
- testy integracyjne: pełny przepływ plik -> analiza -> raport,
- test integralności: źródło ma identyczną treść po analizie.
- negatywne dowody: blokada, DNS, zezwolenie i wzmianka nie stają się połączeniem;
  host URL nie potwierdza pełnego URL; PID nie służy do przypisania skryptu.
- negatywne uruchomienia: `cat`, samo basename, `-Command`, `-c`, `-e`, 4104,
  nieudany Audit exec i inny syscall nie potwierdzają wywołania skryptu.
- adaptery OS są zastępowane atrapami w testach; testy nie odczytują prawdziwych
  dzienników i nie uruchamiają badanych skryptów. Rzeczywisty odczyt Windows
  sprawdzono osobno: niedostępne źródła skutkują wynikiem `NIE SPRAWDZONO`.

## Rozszerzanie

Nowa reguła wymaga co najmniej przykładu pozytywnego i negatywnego dla języka.
Nowy format raportu wymaga walidacji struktury i zapisu atomowego. Adapter
narzędzia zewnętrznego wymaga testu timeoutu, kodu błędu, limitu stdout/stderr i
potwierdzenia `shell=False`.
