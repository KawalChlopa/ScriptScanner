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
| `connections.py` | czas, odczyt z limitami, korelacja | `ConnectionTests` |
| `timing.py` | format UTC, system, NTP, fallback | `TimingTests` |
| `reputation.py` | żądania, limit JSON, mapowanie, błędy | `ReputationTests` |
| `reporting.py` | nazwy, terminal, JSON/PDF, atomowy zapis | `ReportingTests` |
| `pipeline.py` | scalanie, analiza, zapis, ostrzeżenia | `PipelineTests` |
| `cli.py` | formaty, parser, konfiguracja, kody wyjścia | `CliTests` |

## Kategorie

- testy jednostkowe: deterministyczne reguły i transformacje,
- testy granic: rozmiary, liczba linii, kodowania, niepoprawny JSON/PDF input,
- testy bezpieczeństwa: brak sieci dzięki atrapom, sanitacja terminala i PDF,
- testy integracyjne: pełny przepływ plik -> analiza -> raport,
- test integralności: źródło ma identyczną treść po analizie.

## Rozszerzanie

Nowa reguła wymaga co najmniej przykładu pozytywnego i negatywnego dla języka.
Nowy format raportu wymaga walidacji struktury i zapisu atomowego. Adapter
narzędzia zewnętrznego wymaga testu timeoutu, kodu błędu, limitu stdout/stderr i
potwierdzenia `shell=False`.
