# Architektura

## Kontekst

Infa-Sled jest lokalnym programem z dwoma punktami wejścia: analizatorem plików
oraz monitorem bieżących połączeń. Granicą zaufania jest proces Pythona: plik
skryptu, logi i dane systemowe są niezaufanymi danymi, a katalog wynikowy jest
jedynym miejscem zapisu. Rdzeń nie wymaga usług ani bazy danych.

## Przepływ danych

```mermaid
flowchart TD
    A[Niezaufany skrypt] --> B[Odczyt z limitami]
    B --> C[Identyfikacja języka i skróty]
    C --> D[Detekcja obfuskacji]
    D --> E[Pasywna defuskacja kopii]
    C --> F[Reguły statyczne]
    E --> F
    C --> G[Ekstrakcja IOC]
    E --> G
    H[Jawnie podane logi] --> I[Parser tekstu z limitami]
    I --> J[Korelacja dokładna]
    G --> J
    G -. tylko z flagą sieciową .-> K[VT lub URLhaus]
    L[Zegar systemowy / opcjonalny NTP] --> M[Agregacja wyniku]
    F --> M
    D --> M
    J --> M
    K --> M
    M --> N[Raport terminalowy]
    M --> O[JSON]
    M --> P[PDF]
    M --> Q[Kopia po defuskacji]
    R[Windows lub Linux] --> S[psutil: migawka TCP/UDP]
    S --> T[Normalizacja i przypisanie PID/procesu]
    T --> U[Terminal]
    T --> V[connections.jsonl]
    V --> I
```

## Moduły

| Moduł | Odpowiedzialność | Wejście | Wyjście |
|---|---|---|---|
| `config.py` | walidacja konfiguracji i bramki sieciowej | wartości CLI | `AnalysisConfig` |
| `fileio.py` | limitowany odczyt, kodowanie, język, skróty | ścieżka | `ScriptInput` |
| `rules.py` | deterministyczne reguły podejrzanego kodu | tekst, język | `Finding[]` |
| `obfuscation.py` | sygnały i bezpieczne transformacje literałów | tekst | sygnały, kopia, transformacje |
| `ioc.py` | URL, domeny, IPv4 i normalizacja | tekst | `IOC[]` |
| `sanitization.py` | rozbrajanie URL, domen i IPv4/IPv6 przed wyjściem | tekst/struktura | bezpieczna prezentacja |
| `connections.py` | odczyt logów i korelacja | logi, IOC | `ConnectionMatch[]` |
| `system_monitor.py` | bieżące migawki TCP/UDP i raport JSONL | tabele gniazd systemu | `LiveConnection[]` |
| `timing.py` | UTC i opcjonalny NTP | konfiguracja | `TimestampInfo` |
| `reputation.py` | opcjonalny odczyt reputacji | IOC | `ReputationResult[]` |
| `pipeline.py` | kolejność etapów i odporność | plik, konfiguracja | `AnalysisResult` |
| `reporting.py` | prezentacja, serializacja i atomowy zapis | wynik | terminal, JSON, PDF, tekst |
| `main.py` | główny interfejs użytkownika i kody wyjścia | argumenty | komunikaty i artefakty |
| `models.py` | kontrakty między modułami | - | dataclasses |

Monitor i analizator są rozdzielone. Monitor nie importuje ani nie uruchamia
skryptu, a analizator nie wymaga uprawnień systemowych. Jedynym punktem
połączenia jest plik `connections.jsonl`, który parser logów traktuje jak każde
inne niezaufane wejście.

## Kontrakty

- `AnalysisResult.schema_version` ma obecnie wartość `1.0`.
- Kolekcje w modelach są krotkami, co ogranicza przypadkową mutację.
- Każda detekcja ma stabilny `rule_id`, ważność, linię i fragment dowodu.
- IOC przechowuje pochodzenie: `original`, `deobfuscated` lub
  `connection-log`.
- Wyniki pośrednie i raporty nigdy nie nadpisują źródła.
- `LiveConnection` opisuje obserwację, nie niepodważalny zapis pakietu; brak
  rekordu nie oznacza braku wcześniejszego połączenia.
- Surowe IOC istnieją tylko w modelu roboczym. Granica wyjściowa rozbraja je do
  `hxxp(s)`, `[.]` i `[:]`; parser wejściowy normalizuje te znaczniki tylko w
  pamięci, aby zachować możliwość korelacji.

## Rozszerzalność

Nowy język wymaga: mapy rozszerzeń i heurystyk w `fileio.py`, reguł z testami,
aktualizacji ekstrakcji/defuskacji, testu integracyjnego i aktualizacji macierzy
wymagań. Zewnętrzny silnik analizy powinien być osobnym adapterem zwracającym
modele `Finding`; musi działać z `shell=False`, limitem czasu i ograniczonym
wyjściem. Decyzja o braku obowiązkowych adapterów zewnętrznych jest opisana w
`docs/decisions/0001-standard-library-core.md`.
