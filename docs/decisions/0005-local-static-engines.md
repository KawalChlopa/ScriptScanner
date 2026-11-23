# ADR-0005 — Lokalne silniki analizy statycznej

- Status: zaakceptowany
- Data: 2026-11-23

## Kontekst

Reguły tekstowe wykrywają oznaki obfuskacji i niektóre sygnatury. Rozpoznanie
rzeczywistych wywołań wymaga analizy składni. Projekt przewiduje pięć
silników dostępnych lokalnie na różnych platformach.

## Decyzja

YARA dostarcza sygnatury bajtowe. Semgrep dopasowuje lokalne wzorce
strukturalne w Bash i JavaScript. ShellCheck wnosi diagnostykę Bash.
Esprima i PowerShell Parser API pozwalają odczytać wybrane wywołania z AST.
Biblioteki YARA i Esprima są uruchamiane w osobnych procesach CPython.
PowerShell uruchamia stały program, który przyjmuje dane na stdin,
a Semgrep otrzymuje kopię tekstu i reguły w prywatnym katalogu.

Pakiet `static-analysis` instaluje trzy zależności Pythona. Operator
instaluje narzędzia systemowe dla używanych języków. Rdzeń nadal działa
z biblioteką standardową. Każda dostępna integracja działa automatycznie.
Wyniki są mapowane na `Finding`, a pokrycie jest jawne w `EngineRun`.

## Konsekwencje

Każda reprezentacja skryptu ma osobny przebieg, więc częściowy wynik po
defuskacji nie wpływa na stan oryginału. Niepełna analiza jest raportowana.
Ochrona przed odczytem dodatkowych zasobów ogranicza analizę PowerShell dla
niektórych tekstów. Esprima ma ograniczony zakres obsługiwanej wersji ECMAScript.
Zadanie CI weryfikuje zestaw na zainstalowanych silnikach.
