# Historyczne dowody połączeń i wywołania skryptu

Źródła są jawnie wskazywane przez `--connection-log`/`--execution-log` albo
jednorazowo odczytywane przez `--system-history`. Obie flagi plikowe używają
wspólnego parsera; ten sam plik jest odczytywany tylko raz.

## Co oznacza wynik połączenia

| Status JSON | Znaczenie |
|---|---|
| `confirmed` | zarejestrowane zdarzenie połączenia, np. wychodzące Sysmon 3 |
| `request-observed` | żądanie URL, bez dowodu poprawnej odpowiedzi |
| `blocked` | zablokowana próba, np. Security 5157 |
| `allowed` | zezwolenie, np. Security 5156; nie dowodzi nawiązania połączenia |
| `dns-only` | zapytanie DNS; nie dowodzi połączenia |
| `host-only` | dowód dotyczący hosta URL, nie pełnego URL |
| `mentioned-only` | adres wystąpił w tekście bez rozpoznanego zdarzenia |
| `not-observed` | rozpoznano zdarzenia sieciowe, ale nie znaleziono dowodu dla IOC |
| `not-checked` | brak odpowiednich zdarzeń sieciowych |

Status podsumowuje najmocniejszy rodzaj dowodu. `evidence_types` i
`connection_matches` zachowują wszystkie rodzaje, w tym współwystępujące
blokady i połączenia. Zdarzenie połączenia TCP/UDP nie oznacza poprawnej
odpowiedzi aplikacji, przesłania danych ani wykonania instrukcji skryptu.
Pełny URL i jego host są rozróżniane. Parser nie wykonuje DNS w celu
odgadnięcia historycznego adresu IP domeny.

## Dowody wywołania skryptu

`execution_check.status`: `confirmed`, `not-observed`, `not-checked`.
Potwierdzenie oznacza zdarzenie utworzenia procesu z dokładną ścieżką
argumentu skryptu albo jawny `script_sha256` zgodny z badanym plikiem.

- Sysmon 1 i Security 4688: interpreter oraz argument `-File` PowerShell lub
  bezpośredni argument pliku dla Bash/sh/dash/zsh/Node. Nie interpretujemy
  `-Command`, `-EncodedCommand`, `-c`, `-e`, zagnieżdżonych poleceń ani nieznanych opcji.
- Linux Audit: powiązane `SYSCALL` (`success=yes`, execve/execveat), `EXECVE`
  i opcjonalne `CWD`. Numery wywołań są mapowane dla x86-64, i386 i aarch64.
- Sama nazwa pliku, wzmianka w komendzie `cat`, historia powłoki i 4104 nie
  potwierdzają wywołania. Hash `Hashes` z Sysmon dotyczy obrazu procesu,
  zwykle interpretera, i nie jest używany jako hash skryptu.

Ścieżki Windows porównujemy bez uwzględniania wielkości liter, POSIX z jej
uwzględnieniem. Względna ścieżka wymaga znanego absolutnego `cwd`.
`--original-script-path` wskazuje oryginalną absolutną ścieżkę skopiowanej próbki.
Zgodna ścieżka nie dowodzi zgodnej historycznej zawartości. Nawet utworzenie
procesu z argumentem pliku nie dowodzi, że interpreter pomyślnie go odczytał
ani że skrypt zakończył działanie.

`script_related` przy dowodzie sieciowym jest prawdziwe tylko przy zgodnym
hoście i `ProcessGuid` ze zdarzeniem wywołania. Sam PID jest niewystarczający
(może być ponownie użyty). Przypisanie dotyczy procesu, nie konkretnej instrukcji.

## Formaty plików

XML Windows (`Event` lub `Events`), JSONL, CSV, surowy Linux Audit i zwykły
tekst. Kodowanie UTF-8 lub UTF-16 z BOM. Limity: 10 MB i 100 000 wierszy.
DTD i deklaracje encji XML są odrzucane. Binarny `.evtx` wymaga eksportu do XML;
odczyt bieżących dzienników Windows przez `--system-history` wykonuje ten etap
narzędziem `wevtutil`.

Własny kontrakt JSONL/CSV ma pole `event_type` o wartości `connected`,
`allowed`, `blocked`, `dns-query`, `url-request`, `mentioned`, `process-start`
lub `script-block`. JSONL może zawierać:

```json
{"event_type":"process-start","timestamp":"2026-11-15T10:00:00Z","image":"bash","argv":["bash","/tmp/demo.sh"],"cwd":"/tmp","host":"DEMO","process_guid":"unique-process"}
```

Pozostałe pola: `address`, `command_line`, `script_path`, `script_sha256`.
`script_path` oznacza plik przekazany do wykonania; `script_sha256` dotyczy
wyłącznie tego skryptu. Pola tekstowe muszą być ciągami, `argv` listą ciągów.
CSV obsługuje pola tekstowe; do listy `argv` użyj JSONL.
Prosty tekst rozpoznaje jawne `action=connected|allowed|blocked` oraz
`destination_ip=`, `dst=`, `url=`. Bez tych danych adres pozostaje wzmianką.

## Odczyt systemu

```cmd
python src\main.py sample.ps1 --system-history --history-hours 24 --history-max-events 1000 --mode raport
```

Windows: `wevtutil qe`, Sysmon (1, 3, 22) i Security (4688, 5156, 5157).
Tylko wychodzące zdarzenia sieciowe; 5156 pozostaje zezwoleniem.
Linux: `journalctl --system -o json`, wychodzące UFW ALLOW/BLOCK, XML Sysmon
w `MESSAGE` oraz grupy Linux Audit. Dodatkowo odczyt bieżącego
`/var/log/audit/audit.log` (bez plików rotowanych). Żaden adapter nie zakłada,
że system domyślnie rejestrował cały ruch lub wszystkie wykonania.

Domyślnie ostatnie 24 h i 1000 wpisów na dziennik; dopuszczalne zakresy:
1–8760 h oraz 1–10000 wpisów. Dla `audit.log` limit dotyczy rozpoznanych
zdarzeń po odczycie pliku do 10 MB. Dla `journalctl` limit dotyczy wszystkich
zwróconych wpisów, więc inne komunikaty mogą wyprzeć istotne zdarzenia.
Pole `history_sources` pokazuje źródła, liczbę rozpoznanych zdarzeń i problemy.
Pusty lub niedostępny dziennik nie jest dowodem braku aktywności.

Program nie instaluje usług, nie włącza audytu, nie podnosi uprawnień i nie
monitoruje w tle. Niektóre odczyty wymagają administratora/roota. Timeout
narzędzia wynosi 10 s; limity stdout/stderr wynoszą 10 MB/64 KB, sprawdzane
również podczas działania. Dane chwilowo trafiają do prywatnych plików
tymczasowych, które są zamykane po odczycie. Wszystkie wyjścia rozbrajają IOC.

## Źródła znaczenia zdarzeń

- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Security 5156](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156)
- [wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
- [Linux Audit](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
