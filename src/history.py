"""Jednorazowy odczyt dowodow historycznych; nigdy nie wykonuje badanego pliku."""

from __future__ import annotations

import csv
import io
import json
import ntpath
import os
import platform
import posixpath
import re
import shlex
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from errors import InputFileError
from ioc import extract_iocs
from models import ExecutionCheck, ExecutionMatch, HistoryEvent, HistorySource, ScriptInput

MAX_BYTES = 10_000_000
NETWORK_TYPES = frozenset({"connected", "allowed", "blocked", "dns-query", "url-request"})
EVENT_TYPES = NETWORK_TYPES | {"mentioned", "process-start", "script-block"}
TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")


def source_summary(name: str, events: tuple[HistoryEvent, ...], detail: str = "") -> HistorySource:
    """Opisuje rzeczywiscie rozpoznane dane; samo otwarcie pliku nie jest pokryciem."""
    return HistorySource(
        name, "read" if events else "empty", len(events),
        sum(event.event_type in NETWORK_TYPES for event in events),
        sum(event.event_type == "process-start" for event in events), detail,
    )


def windows_events(text: str, source: str) -> tuple[HistoryEvent, ...]:
    """Czyta XML Sysmon/Security/PowerShell po nazwach pol, bez lokalizowanych opisow."""
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise InputFileError("Deklaracje DTD/ENTITY w logu sa niedozwolone")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise InputFileError(f"Niepoprawny XML logu: {source}") from error
    events = []
    for node in root.iter():
        node.tag = node.tag.rsplit("}", 1)[-1]
    for node in ([root] if root.tag == "Event" else root.findall(".//Event")):
        system = node.find("System")
        if system is None:
            continue
        provider = system.find("Provider")
        provider_name = provider.get("Name", "") if provider is not None else ""
        event_id = system.findtext("EventID", "")
        data = {item.get("Name", ""): item.text or "" for item in node.findall(".//EventData/Data")}
        time = system.find("TimeCreated")
        timestamp = time.get("SystemTime") if time is not None else None
        host = system.findtext("Computer", "")
        guid = data.get("ProcessGuid", "")
        process_key = f"{host}|{guid}" if host and guid else None
        kind, address = "", ""
        if provider_name == "Microsoft-Windows-Sysmon":
            if event_id == "1":
                kind = "process-start"
            elif event_id == "3" and data.get("Initiated", "").lower() == "true":
                kind, address = "connected", data.get("DestinationIp", "")
            elif event_id == "22":
                kind, address = "dns-query", data.get("QueryName", "")
        elif provider_name == "Microsoft-Windows-Security-Auditing":
            if event_id == "4688":
                kind = "process-start"
            elif event_id in {"5156", "5157"} and data.get("Direction") in {"%%14593", "Outbound"}:
                kind = "allowed" if event_id == "5156" else "blocked"
                address = data.get("DestAddress", "")
        elif provider_name == "Microsoft-Windows-PowerShell" and event_id == "4104":
            kind = "script-block"
        if kind:
            events.append(HistoryEvent(
                kind, timestamp, source, address=address,
                image=data.get("Image", data.get("NewProcessName", "")),
                command_line=data.get("CommandLine", ""), cwd=data.get("CurrentDirectory", ""),
                script_path=data.get("Path", ""), process_key=process_key,
                raw=f"{provider_name} EventID={event_id}",
            ))
    return tuple(events)


def normalized_event(data: dict, source: str) -> HistoryEvent | None:
    """Czyta jawny kontrakt JSONL/CSV; hash obrazu procesu nie jest hashem skryptu."""
    kind = data.get("event_type")
    if not isinstance(kind, str) or kind not in EVENT_TYPES:
        return None
    keys = ("timestamp", "address", "image", "command_line", "script_path", "script_sha256", "cwd")
    if any(not isinstance(data.get(key, ""), str) for key in keys):
        raise InputFileError(f"Niepoprawne typy pol historii: {source}")
    argv = data.get("argv", [])
    if not isinstance(argv, list) or any(not isinstance(arg, str) for arg in argv):
        raise InputFileError(f"Pole argv musi byc lista tekstow: {source}")
    # ProcessGuid + host jest globalnym kluczem; sam PID moze zostac uzyty ponownie.
    host, guid = data.get("host"), data.get("process_guid")
    process_key = f"{host}|{guid}" if isinstance(host, str) and host and isinstance(guid, str) and guid else None
    return HistoryEvent(
        kind, data.get("timestamp") or None, source,
        **{key: data.get(key, "") for key in keys if key != "timestamp"},
        process_key=process_key, raw=f"event_type={kind}", argv=tuple(argv),
    )


def audit_events(text: str, source: str) -> tuple[HistoryEvent, ...]:
    """Laczy rekordy Linux Audit po identyfikatorze; uznaje tylko udane execve."""
    groups: dict[tuple[str, str], list[str]] = {}
    for line in text.splitlines():
        if line.lstrip().startswith("{"):
            continue
        match = re.search(r"\btype=(SYSCALL|EXECVE|CWD)\b.*?msg=audit\((\d+(?:\.\d+)?:\d+)\)", line)
        if match:
            node = re.search(r"\bnode=(\S+)", line)
            groups.setdefault((node.group(1) if node else "", match.group(2)), []).append(line)
    events = []
    for (node, key), lines in groups.items():
        syscall = next((line for line in lines if "type=SYSCALL " in line), "")
        fields = dict(re.findall(r'(\w+)=("[^"]*"|\S+)', syscall))
        if fields.get("success") != "yes":
            continue
        exec_calls = {"c000003e": {"59", "322"}, "40000003": {"11", "358"}, "c00000b7": {"221", "281"}}
        if fields.get("syscall") not in exec_calls.get(fields.get("arch"), set()):
            continue
        exec_lines = [line for line in lines if "type=EXECVE " in line]
        if not exec_lines:
            continue
        args = {}
        for line in exec_lines:
            for number, value in re.findall(r'\ba(\d+)=("[^"]*"|[^\s]+)', line):
                try:
                    args[int(number)] = value[1:-1] if value.startswith('"') else bytes.fromhex(value).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    args = {}
                    break
        if not args or sorted(args) != list(range(len(args))):
            continue
        cwd_line = next((line for line in lines if "type=CWD " in line), "")
        cwd = re.search(r'\bcwd="([^"]*)"', cwd_line)
        try:
            timestamp = datetime.fromtimestamp(float(key.split(":")[0]), timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            continue
        events.append(HistoryEvent(
            "process-start", timestamp, source, image=fields.get("exe", "").strip('"'),
            cwd=cwd.group(1) if cwd else "", argv=tuple(args[i] for i in range(len(args))),
            raw=f"Linux Audit node={node or 'local'} event={key}",
        ))
    return tuple(events)


def parse_history(text: str, source: str, max_lines: int = 100000) -> tuple[HistoryEvent, ...]:
    """Czyta XML, JSONL/CSV, auditd i tekst; sama wzmianka nie potwierdza polaczenia."""
    if len(text.encode("utf-8")) > MAX_BYTES or len(text.splitlines()) > max_lines:
        raise InputFileError(f"Log przekracza limit rozmiaru lub wierszy: {source}")
    if text.lstrip().startswith("<"):
        return windows_events(text, source)
    events = list(audit_events(text, source))
    lines = text.splitlines()
    if lines and "event_type" in lines[0] and "," in lines[0] and not lines[0].lstrip().startswith("{"):
        return tuple(event for row in csv.DictReader(io.StringIO(text)) if (event := normalized_event(row, source)))
    audit_messages = []
    for line in lines:
        journal_timestamp = None
        if not line.lstrip().startswith("{") and re.search(r"\btype=(SYSCALL|EXECVE|CWD)\b.*msg=audit\(", line):
            continue
        if line.lstrip().startswith("{"):
            try:
                data = json.loads(line)
            except (ValueError, RecursionError) as error:
                raise InputFileError(f"Niepoprawny JSONL logu: {source}") from error
            if not isinstance(data, dict):
                raise InputFileError(f"Wiersz JSONL musi byc obiektem: {source}")
            event = normalized_event(data, source)
            if event:
                events.append(event)
                continue
            # journalctl -o json: interpretujemy MESSAGE, nie techniczne metadane.
            if "MESSAGE" in data:
                message = data["MESSAGE"]
                if not isinstance(message, str):
                    continue
                if "<Event" in message:
                    events.extend(windows_events(message[message.index("<Event"):], source))
                    continue
                if "type=" in message and "msg=audit(" in message:
                    # pelne grupy Audit sa laczone w drugim przebiegu ponizej.
                    audit_messages.append(message)
                    continue
                line = message
                try:
                    journal_timestamp = datetime.fromtimestamp(int(data["__REALTIME_TIMESTAMP"]) / 1000000, timezone.utc).isoformat()
                except (KeyError, TypeError, OverflowError, OSError, ValueError):
                    pass
        timestamp_match = TIME_RE.search(line)
        timestamp = timestamp_match.group(0) if timestamp_match else journal_timestamp
        action = re.search(r"\baction=(connected|allowed|blocked)\b", line, re.I)
        kind = action.group(1).lower() if action else "mentioned"
        if "[UFW BLOCK]" in line:
            kind = "blocked"
        elif "[UFW ALLOW]" in line:
            kind = "allowed"
        if "[UFW " in line:
            direction = re.search(r"\bIN=(\S*)\s+OUT=(\S*)", line)
            if not direction or direction.group(1) or not direction.group(2):
                kind = "mentioned"
        destination = re.search(r"\b(?:destination_ip|dst|DST|url)=([^\s]+)", line)
        observables = extract_iocs(destination.group(1) if destination else line, "history")
        for item in observables:
            events.append(HistoryEvent(kind, timestamp, source, address=item.value, raw=line[:1000]))
    # journalctl moze przechowywac poszczegolne rekordy tego samego zdarzenia Audit.
    events.extend(audit_events("\n".join(audit_messages), source))
    return tuple(events)


def read_history_log(path: Path | str, max_bytes: int = MAX_BYTES, max_lines: int = 100000) -> tuple[HistoryEvent, ...]:
    """Odczytuje ograniczony plik UTF-8/UTF-16 z BOM; binarny EVTX wymaga eksportu."""
    resolved = Path(path).expanduser().resolve()
    try:
        with resolved.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise InputFileError(f"Log przekracza limit {max_bytes} bajtow")
        encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        return parse_history(raw.decode(encoding), str(resolved), max_lines)
    except (OSError, UnicodeDecodeError) as error:
        raise InputFileError(f"Nie mozna odczytac logu {resolved}: {error}") from error


def canonical_path(value: str, cwd: str = "") -> str:
    """Porownuje sciezki zgodnie z OS zapisanym w danych, bez dostepu do pliku."""
    windows = bool(re.match(r"^[A-Za-z]:[\\/]", value) or "\\" in value or re.match(r"^[A-Za-z]:", cwd))
    path_module = ntpath if windows else posixpath
    if not path_module.isabs(value):
        if not path_module.isabs(cwd):
            return ""
        value = path_module.join(cwd, value)
    value = path_module.normpath(value)
    return ntpath.normcase(value) if windows else value


def script_argument(event: HistoryEvent) -> str:
    """Wydobywa argument pliku dla znanych interpreterow; nie uznaje -Command/-c/-e."""
    if event.script_path:
        return event.script_path
    try:
        windows = bool("\\" in event.image or event.image.lower().endswith(".exe") or re.match(r"^[A-Za-z]:", event.cwd))
        args = list(event.argv) or (re.findall(r'"[^\"]*"|\S+', event.command_line) if windows else shlex.split(event.command_line))
        args = [arg.strip('"') for arg in args]
        if not args:
            return ""
        image = ntpath.basename(event.image or args[0]).lower()
        # Linux Audit moze zapisac oryginalny execve pliku z shebangiem:
        # argv[0] jest wtedy skryptem, a nie nazwa interpretera.
        shebang_extensions = {"bash": (".sh", ".bash"), "sh": (".sh",), "dash": (".sh",),
                              "zsh": (".sh", ".zsh"), "node": (".js",), "nodejs": (".js",)}
        if event.argv and args[0].lower().endswith(shebang_extensions.get(image, ())) and not windows:
            return args[0]
        if image in {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}:
            lowered = [arg.lower() for arg in args]
            flags = {"-noprofile", "-nop", "-noninteractive", "-noni", "-nologo", "-noexit", "-sta", "-mta"}
            values = {"-executionpolicy", "-ep", "-windowstyle", "-w", "-inputformat", "-outputformat", "-configurationname", "-workingdirectory"}
            index = 1
            while index < len(args):
                arg = lowered[index]
                if arg == "-file":
                    return args[index + 1]
                if arg in flags:
                    index += 1
                elif arg in values:
                    index += 2
                else:
                    return ""
            return ""
        if image not in {"bash", "sh", "dash", "zsh", "node", "node.exe", "nodejs"}:
            return ""
        # Tylko jawny argument pliku; nie zgadujemy znaczenia nieznanych opcji.
        for arg in args[1:]:
            if arg in {"--", "--noprofile", "--norc"}:
                continue
            if arg.startswith("-"):
                return ""
            return arg
    except (ValueError, IndexError):
        pass
    return ""


def assess_execution(script: ScriptInput, events: tuple[HistoryEvent, ...], checked_count: int,
                     original_path: str | None = None) -> ExecutionCheck:
    """Wskazuje dowod wywolania po dokladnej sciezce albo hashu skryptu, nie nazwie."""
    matches = []
    target = canonical_path(original_path or str(script.path))
    if original_path and not target:
        raise InputFileError("Oryginalna sciezka skryptu musi byc absolutna")
    for event in events:
        if event.event_type != "process-start":
            continue
        argument = script_argument(event)
        same_path = bool(target and canonical_path(argument, event.cwd) == target)
        same_hash = bool(event.script_sha256 and event.script_sha256.lower() == script.hashes.sha256)
        if same_path or same_hash:
            identity = "script-sha256" if same_hash else "script-path"
            detail = "Wywolanie skryptu w zdarzeniu utworzenia procesu; nie dowodzi zakonczenia wykonania."
            if same_path and not same_hash:
                detail += " Zgodna sciezka, brak potwierdzenia historycznej zawartosci pliku."
            matches.append(ExecutionMatch(event.timestamp, event.log_source, identity, detail, event.process_key))
    unique = tuple(dict.fromkeys(matches))
    return ExecutionCheck("confirmed" if unique else "not-observed" if checked_count else "not-checked", checked_count, unique)


def run_history_command(args: list[str], timeout: float = 10.0) -> str:
    """Wywoluje tylko zaufane narzedzie odczytu, z limitem czasu i wyjscia."""
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            with subprocess.Popen(args, shell=False, stdout=output, stderr=errors) as process:
                deadline = time.monotonic() + timeout
                try:
                    while True:
                        if os.fstat(output.fileno()).st_size > MAX_BYTES or os.fstat(errors.fileno()).st_size > 65536:
                            raise InputFileError("Wyjscie narzedzia historii przekracza limit")
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(args[0], timeout)
                        try:
                            process.wait(timeout=min(0.05, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            continue
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                if process.returncode:
                    raise subprocess.CalledProcessError(process.returncode, args[0])
                if os.fstat(errors.fileno()).st_size > 65536:
                    raise InputFileError("Wyjscie bledow narzedzia historii przekracza limit")
            output.seek(0)
            raw = output.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InputFileError("Odpowiedz narzedzia historii przekracza limit 10 MB")
        encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-16-le" if raw.startswith(b"<\x00") else "utf-8-sig"
        return raw.decode(encoding)
    except subprocess.CalledProcessError as error:
        reason = "brak uprawnien" if error.returncode == 5 else "brak dziennika lub blad zapytania"
        raise InputFileError(f"Odczyt historii: {reason} (kod {error.returncode})") from error
    except (OSError, UnicodeDecodeError, subprocess.SubprocessError) as error:
        raise InputFileError(f"Odczyt historii nie powiodl sie ({type(error).__name__}); sprawdz uprawnienia i dziennik") from error


def collect_system_history(hours: int = 24, max_events: int = 1000) -> tuple[tuple[HistoryEvent, ...], tuple[HistorySource, ...]]:
    """Jednorazowo odczytuje istniejace dzienniki; nie wlacza audytu ani uslug."""
    if not 1 <= hours <= 8760 or not 1 <= max_events <= 10000:
        raise InputFileError("Niepoprawne limity historii systemowej")
    commands = []
    system = platform.system()
    if system == "Windows":
        executable = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "wevtutil.exe")
        for channel, ids in (("Microsoft-Windows-Sysmon/Operational", (1, 3, 22)), ("Security", (4688, 5156, 5157))):
            ids_query = " or ".join(f"EventID={number}" for number in ids)
            query = f"*[System[({ids_query}) and TimeCreated[timediff(@SystemTime) <= {hours * 3600000}]]]"
            commands.append((channel, [executable, "qe", channel, f"/q:{query}", "/f:xml", "/e:Events", "/rd:true", "/uni:true", f"/c:{max_events}"]))
    elif system == "Linux":
        commands.append(("system-journal", ["journalctl", "--system", "--no-pager", "--quiet", "--output=json", f"--since=-{hours}h", f"--lines={max_events}"]))
    else:
        return (), (HistorySource(system, "unavailable", 0, detail="Nieobslugiwany system"),)
    events, sources = [], []
    for name, command in commands:
        try:
            text = run_history_command(command)
            parsed = parse_history(text, name)
            events.extend(parsed)
            detail = f"Ostatnie {hours} h; limit {max_events} wpisow; historia moze byc niepelna, audyt mogl byc wylaczony."
            sources.append(source_summary(name, parsed, detail))
        except InputFileError as error:
            sources.append(HistorySource(name, "unavailable", 0, detail=str(error)))
    if system == "Linux":
        audit_path = Path("/var/log/audit/audit.log")
        try:
            audit_events_read = read_history_log(audit_path)
            cutoff = datetime.now(timezone.utc).timestamp() - hours * 3600
            recent = tuple(event for event in audit_events_read if event.timestamp and
                           datetime.fromisoformat(event.timestamp).timestamp() >= cutoff)
            parsed = recent[-max_events:]
            events.extend(parsed)
            sources.append(source_summary(str(audit_path), parsed,
                           f"Ostatnie {hours} h; ostatnie {max_events} rozpoznanych zdarzen; tylko biezacy plik audit.log."))
        except InputFileError as error:
            sources.append(HistorySource(str(audit_path), "unavailable", 0, detail=str(error)))
    return tuple(events), tuple(sources)
