# ADR-0004: jednorazowy odczyt i semantyka dowodów historycznych

Status: przyjęta, 2026-11-15.

## Kontekst

Wystąpienie IOC w dowolnym tekście nie dowodzi połączenia. Użytkownik potrzebuje
raportu o aktywności sieciowej i wywołaniu badanego skryptu na podstawie
istniejących dowodów, z możliwością odczytu Windows/Linux.

## Decyzja

Wspólny model HistoryEvent dla plików i jednorazowego odczytu systemu. Odczyt OS
jest jawny (`--system-history`), ograniczony czasowo i ilościowo. Korzystamy
z wbudowanych narzędzi `wevtutil qe`, `journalctl` i bieżącego audit.log.
Nie dodajemy pakietów runtime, monitora, automatycznej instalacji ani zmiany audytu.
Narzędzia otrzymują stałe argumenty adaptera i walidowane limity; nigdy treść próbki.

Typ dowodu decyduje o wyniku. Blokada, zezwolenie, DNS, host URL i wzmianka
nie są podnoszone do potwierdzenia pełnego połączenia/URL. Wszystkie dopasowania
pozostają w raporcie. Brak odpowiedniego źródła nie jest negatywnym wynikiem.

Wywołanie skryptu wymaga zdarzenia utworzenia procesu z argumentem pliku po
pełnej ścieżce (z CWD) lub jawnego SHA-256 skryptu. Hash obrazu interpretera,
basename, historia powłoki i sam 4104 nie wystarczają. Do związku z siecią
wymagamy hosta i ProcessGuid; PID nie zapewnia tożsamości historycznej.

## Konsekwencje

Zachowujemy obsługę materiału z innej maszyny i powtarzalną demonstrację.
Dostępność dowodów zależy od wcześniejszego audytu i uprawnień. Utworzenie
procesu z plikiem dowodzi wywołania, nie udanego odczytu lub ukończenia skryptu.
Nie odtwarzamy historycznych mapowań DNS, rotowanych Audit ani skasowanych logów.
Testy adapterów używają atrap; rzeczywiste odczyty nie są częścią CI.
