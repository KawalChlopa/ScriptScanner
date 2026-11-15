# AGENTS.md

## Zakres

Te zasady obowiązują w całym repozytorium.

## Cel projektu

Repozytorium zawiera lokalny system CLI do pasywnej analizy skryptów PowerShell,
JavaScript i Bash. System ma wykrywać podejrzane konstrukcje i obfuskację,
bezpiecznie dekodować wybrane literały, wyodrębniać IOC, korelować je z
dostarczonymi logami oraz generować raport terminalowy i pliki JSON/PDF.

## Niezmienniki bezpieczeństwa

1. Nigdy nie uruchamiaj analizowanego skryptu ani jego fragmentu.
2. Nie przekazuj niezaufanej zawartości do `eval`, `exec`, interpretera,
   `subprocess`, powłoki ani parsera wykonującego makra lub rozszerzenia.
3. Jeżeli integracja z zewnętrznym narzędziem zostanie dodana, używaj listy
   argumentów, `shell=False`, limitu czasu i kontroluj kod zakończenia.
4. Oryginalny plik wejściowy pozostaje niezmieniony. Dane pochodne zapisuj
   wyłącznie w katalogu wynikowym.
5. Rdzeń analizy działa bez sieci. Każda komunikacja sieciowa wymaga jawnej
   opcji użytkownika i jest opisana w `docs/SECURITY.md`.
6. Limity rozmiaru, czasu i ilości danych muszą być walidowane na granicach
   systemu.

## Zasady implementacji

- Python 3.11+; biblioteka standardowa jest domyślnym wyborem.
- Kod produkcyjny znajduje się w `src/infa_sled`, testy w `tests`.
- Moduły wymieniają typowane, serializowalne modele z `models.py`.
- Każda nowa lub zmieniona funkcja musi mieć test jednostkowy obejmujący
  poprawny przypadek oraz istotny przypadek brzegowy albo błąd.
- Błąd pojedynczego modułu nie może po cichu unieważnić całej analizy; ma być
  zwrócony jako kontrolowany wyjątek albo ostrzeżenie raportu.
- Reguły detekcji muszą mieć stabilny identyfikator, opis, poziom ważności i
  test pozytywny oraz negatywny.
- Nie dodawaj zależności bez aktualizacji `pyproject.toml`,
  `docs/INFRASTRUCTURE.md` i uzasadnienia w `docs/decisions/`.

## Dokumentacja infrastruktury

Zmiana komponentu, przepływu danych, formatu raportu, zależności, komendy CLI,
CI lub integracji wymaga aktualizacji odpowiednio:

- `README.md` - użycie i szybki start,
- `docs/ARCHITECTURE.md` - komponenty i przepływ danych,
- `docs/INFRASTRUCTURE.md` - pełny inwentarz runtime, CI i zależności,
- `docs/SECURITY.md` - granice zaufania i zagrożenia,
- `docs/REQUIREMENTS_TRACEABILITY.md` - pokrycie wymagań,
- `docs/TESTING.md` - strategia i mapa testów,
- `CHANGELOG.md` - zmiany widoczne dla użytkownika.

## Weryfikacja przed zakończeniem zmiany

Uruchom z katalogu repozytorium:

```powershell
python -m unittest discover -s tests -t . -v
python -m compileall -q src tests
```

Sprawdź także, że przykładowy skrypt jest analizowany bez jego wykonania, a
raporty powstają poza katalogiem źródłowym.
