# ADR-0003: Przenośny monitor połączeń przez psutil

- Status: zaakceptowany
- Data: 2026-11-15

## Kontekst

Projekt ma obserwować bieżące połączenia systemowe na Windowsie i Linuksie oraz
przypisywać je do PID i programu. Implementacje oparte na parsowaniu `netstat`,
PowerShell lub `ss` mają różne formaty, lokalizację komunikatów i wymagają
uruchamiania zewnętrznych procesów. Sam standardowy Python nie udostępnia
przenośnego API dla systemowej tabeli gniazd.

## Decyzja

Monitor używa `psutil>=5.9,<8` i jego `net_connections(kind="inet")`. Zależność
jest jawna w `pyproject.toml` i instalowana z projektem. Analizator statyczny nie
importuje `psutil`; granica niewykonywania analizowanych skryptów pozostaje bez
zmian. Monitor działa tylko do odczytu i generuje JSONL zgodny z istniejącym
parserem logów.

## Konsekwencje

Jedna implementacja działa na Windowsie i Linuksie, bez parsowania tekstowego
wyjścia systemowych poleceń. Kosztem jest obowiązkowa zależność binarna oraz
zależne od systemu i uprawnień braki w widoczności. Migawkowanie może pominąć
bardzo krótkie połączenia i nie zastępuje audytu historycznego ani przechwycenia
pakietów.
