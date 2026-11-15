# ADR-0001: Rdzeń oparty na bibliotece standardowej

- Status: zaakceptowany
- Data: 2026-11-15

## Kontekst

Prototyp ma działać lokalnie, powtarzalnie i bez Internetu. Technologie YARA,
Semgrep, ShellCheck, Esprima i PowerShell Parser API mają różne modele
instalacji i nie są jednocześnie dostępne na wszystkich systemach.

## Decyzja

Rdzeń analizy statycznej używa wyłącznie biblioteki standardowej Pythona.
Detekcje są stabilnymi regułami Regex, a PDF jest generowany lokalnie.
Narzędzia zewnętrzne mogą być później dodane jako opcjonalne adaptery zgodne z
kontraktem `Finding`. Osobny monitor systemowy używa `psutil`; decyzję i granicę
opisuje ADR-0003.

## Konsekwencje

Instalacja i testowanie są proste, a powierzchnia zależności mała. Minusem jest
mniejsza precyzja składniowa niż w pełnych parserach AST; raport i macierz
wymagań mówią o tym wprost.
