# Monitoring systemu i ślady historyczne

## Co robi bieżący monitor

`infa-sled-monitor` działa na Windowsie i Linuksie. Co zadany interwał odczytuje
systemową listę gniazd TCP/UDP i raportuje połączenia, których nie było w
poprzedniej migawce. Zapisuje:

- czas obserwacji UTC,
- protokół, rodzinę IPv4/IPv6 i stan,
- lokalny oraz zdalny adres i port,
- PID, nazwę i ścieżkę programu, jeżeli są dostępne.

Monitor jest tylko do odczytu. Nie przechwytuje treści pakietów, nie wykonuje
DNS, nie odpytuje zdalnych hostów i nie modyfikuje zapory.

## Windows

Instalacja i 30-sekundowy test:

```powershell
python -m pip install .
infa-sled-monitor --duration 30 --interval 1 --mode both
```

Administrator nie jest wymagany do uruchomienia, ale bez niego część informacji
o procesach może być niedostępna. Flaga `--include-unconnected` dołącza porty
nasłuchujące i gniazda UDP bez przypisanego zdalnego adresu.

## Linux

```bash
python3 -m pip install .
infa-sled-monitor --duration 30 --interval 1 --mode both
```

Linux może pominąć gniazda procesów, do których bieżący użytkownik nie ma
dostępu. Gdy pełniejszy obraz jest konieczny, należy użyć zaufanego środowiska
wirtualnego i uruchomić jego konkretny wpis z uprawnieniami roota, na przykład:

```bash
sudo .venv/bin/infa-sled-monitor --duration 30 --interval 1 --mode both
```

Nie należy instalować projektu jako root tylko po to, by uruchomić monitor.

## Korelacja z analizowanym skryptem

Plik `connections.jsonl` jest zgodny z opcją `--connection-log`:

```powershell
infa-sled .\examples\suspicious_obfuscated.ps1 `
  --connection-log .\report\system-connections__...__windows\connections.jsonl
```

Korelacja jest dokładna po znormalizowanym adresie IP, domenie albo URL. Bieżąca
lista gniazd zwykle zawiera IP, a nie pełną domenę czy URL. Dlatego adres IP
wykryty w skrypcie może zostać dopasowany bezpośrednio, ale domena wymaga
dodatkowego logu DNS/proxy albo jawnego rozwiązania nazwy wykonanego poza tym
narzędziem. Narzędzie celowo nie wykonuje DNS za użytkownika.

Adresy w JSONL są celowo rozbrojone, np. `192[.]0[.]2[.]10`. Parser rozpoznaje
ten zapis i odtwarza wartość wyłącznie w pamięci na czas porównania; raport
wynikowy pozostaje rozbrojony.

## Czego monitor nie potrafi udowodnić

- Zdarzenie sprzed uruchomienia monitora nie pojawi się w jego raporcie.
- Połączenie krótsze niż interwał może rozpocząć się i zakończyć między
  migawkami.
- Brak PID lub nazwy nie oznacza braku procesu; przyczyną mogą być uprawnienia
  albo zakończenie procesu w trakcie odczytu.
- Brak rekordu nie jest dowodem, że program lub skrypt nigdy nie był uruchomiony.

## Istniejące ślady historyczne

Historia jest możliwa tylko wtedy, gdy odpowiednie logowanie było włączone
przed zdarzeniem i log nie został usunięty lub nadpisany.

### Windows

- Security Event ID 4688 rejestruje utworzenie procesu, jeżeli działa zasada
  Audit Process Creation. Argumenty są dostępne tylko po osobnym włączeniu
  zapisu linii polecenia.
- Security Event ID 5156 opisuje połączenie dozwolone przez Windows Filtering
  Platform, jeżeli włączono Audit Filtering Platform Connection. Źródło może
  generować dużo zdarzeń.
- PowerShell Operational Event ID 4104 może zawierać bloki skryptów, jeżeli
  wcześniej włączono Script Block Logging.
- Sysmon może rejestrować utworzenie procesu i połączenia sieciowe, ale jest
  oddzielnym narzędziem i wymaga wcześniejszej instalacji oraz konfiguracji.

### Linux

- `auditd` może zapisywać wywołania `execve`, jeśli reguły audytu były aktywne.
- `journald` zawiera zdarzenia usług i programów, które faktycznie do niego
  logują; nie jest automatyczną historią każdego procesu ani gniazda.
- historia powłoki jest poszlaką: może być wyłączona, edytowana, niewpisana na
  dysk albo nie obejmować uruchomień z usług i innych interpreterów.

Bieżąca wersja projektu nie importuje tych uprzywilejowanych dzienników
automatycznie. Pozostają one materiałem do odrębnej analizy kryminalistycznej.

## Źródła techniczne

- [psutil: system-wide network connections](https://psutil.readthedocs.io/stable/#psutil.net_connections)
- [Microsoft: zdarzenie utworzenia procesu 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)
- [Microsoft: Audit Filtering Platform Connection](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-filtering-platform-connection)
- [Red Hat: reguły Linux Audit dla `execve`](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/pdf/risk_reduction_and_recovery_operations/Red_Hat_Enterprise_Linux-10-Risk_reduction_and_recovery_operations-en-US.pdf)
