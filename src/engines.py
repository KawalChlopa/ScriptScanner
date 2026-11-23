"""Ograniczone czasowo adaptery lokalnej analizy statycznej."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from engine_rules import (
    ESPRIMA_WORKER,
    POWERSHELL_WORKER,
    RULE_DETAILS,
    SEMGREP_RULES,
    YARA_RULES,
    YARA_WORKER,
)
from models import EngineRun, Finding

MAX_INPUT_BYTES = 5_000_000
MAX_STDOUT_BYTES = 2_000_000
MAX_STDERR_BYTES = 65_536
MAX_FINDINGS = 500
ENGINE_TIMEOUT = 15.0
PACKAGE_UNAVAILABLE = 79
ENGINES_BY_LANGUAGE = {
    "bash": ("yara", "semgrep", "shellcheck"),
    "javascript": ("yara", "semgrep", "esprima"),
    "powershell": ("yara", "powershell-parser"),
}
SEMGREP_TARGETS = {"bash": "sample.sh", "javascript": "sample.js"}
# These constructs can trigger resolution of modules, assemblies or DSC resources
# during parsing. Reject conservatively even inside literals or comments.
POWERSHELL_DIRECTIVE = re.compile(r"using|configuration|#\s*requires", re.IGNORECASE)
SHELLCHECK_DIRECTIVE = re.compile(r"#[^\S\r\n]*shellcheck")
SHELLCHECK_HEADER = "# shellcheck source=/dev/null\n"
SHELLCHECK_LEVELS = {"error": "medium", "warning": "low", "info": "info", "style": "info"}
PACKAGE_CHECK = (
    "import importlib.util, sys\n"
    "if importlib.util.find_spec({package!r}) is None: sys.exit({code})\n"
)


class EngineError(Exception):
    """Kontrolowany blad narzedzia lub jego protokolu."""


@contextmanager
def engine_temp_directory(directory: Path, prefix: str) -> Iterator[Path]:
    """Ponawia sprzatanie przy krotkotrwalej blokadzie pliku w Windows."""
    temporary = tempfile.TemporaryDirectory(prefix=prefix, dir=directory)
    try:
        yield Path(temporary.name)
    finally:
        deadline = time.monotonic() + 2.0
        while True:
            try:
                temporary.cleanup()
                break
            except PermissionError as error:
                remaining = deadline - time.monotonic()
                if getattr(error, "winerror", None) not in {32, 33} or remaining <= 0:
                    raise
                time.sleep(min(0.05, remaining))


def trusted_executable(name: str, *, python_scripts: bool = False) -> str | None:
    """Szuka tylko plikow wykonywalnych w bezwzglednych wpisach PATH."""
    executable = f"{name}.exe" if os.name == "nt" else name
    entries = os.get_exec_path()
    if python_scripts:
        entries.insert(0, sysconfig.get_path("scripts"))
    for entry in entries:
        path = Path(entry)
        if path.is_absolute():
            resolved = shutil.which(str(path / executable))
            if resolved:
                return resolved
    return None


def engine_command(engine: str) -> list[str] | None:
    """Buduje polecenie z konfiguracji repozytorium i nazw zaufanych narzedzi."""
    if engine in {"yara", "esprima"}:
        check = PACKAGE_CHECK.format(package=engine, code=PACKAGE_UNAVAILABLE)
        python = [sys.executable, "-I", "-X", "utf8", "-c"]
        if engine == "yara":
            return [*python, check + YARA_WORKER, YARA_RULES]
        return [*python, check + ESPRIMA_WORKER]
    if engine == "semgrep":
        executable = trusted_executable("semgrep", python_scripts=True)
        if executable is None:
            return None
        return [
            executable,
            "scan", "--config", "rules.yml", "--json", "--quiet", "--metrics=off",
            "--disable-version-check", "--disable-nosem", "--no-git-ignore",
            "--project-root=.",
            "--no-rewrite-rule-ids", "--jobs=1", "--timeout=5", "--max-memory=512",
            f"--max-target-bytes={MAX_INPUT_BYTES}",
        ]
    if engine == "shellcheck":
        executable = trusted_executable("shellcheck")
        return [executable, "--norc", "--shell=bash", "--format=json", "-"] if executable else None
    executable = trusted_executable("pwsh") or trusted_executable("powershell")
    if executable is None:
        return None
    encoded = base64.b64encode(POWERSHELL_WORKER.encode("utf-16-le")).decode("ascii")
    return [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


def run_engine(
    args: list[str], directory: Path, input_data: bytes, timeout: float = ENGINE_TIMEOUT,
) -> tuple[int, str]:
    """Czyta ograniczone wyjscie z procesu i sprzata po bledzie lub timeoucie."""
    env = {
        key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "LANG")
        if key in os.environ
    }
    env.update({
        "PATH": os.pathsep.join(entry for entry in os.get_exec_path() if Path(entry).is_absolute()),
        "HOME": str(directory),
        "USERPROFILE": str(directory),
        "TMPDIR": str(directory),
        "TMP": str(directory),
        "TEMP": str(directory),
        "SEMGREP_SETTINGS_FILE": str(directory / "semgrep-settings.yml"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(directory / "gitconfig"),
        "OTEL_SDK_DISABLED": "true",
        "POWERSHELL_TELEMETRY_OPTOUT": "1",
        "POWERSHELL_UPDATECHECK": "Off",
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
    })
    with (
        engine_temp_directory(directory, "stdio-") as io_directory,
        (io_directory / "stdin").open("x+b") as source,
        (io_directory / "stdout").open("x+b") as output,
        (io_directory / "stderr").open("x+b") as errors,
    ):
        source.write(input_data)
        source.seek(0)
        with subprocess.Popen(
            args, cwd=directory, env=env, shell=False, stdin=source, stdout=output, stderr=errors,
        ) as process:
            deadline = time.monotonic() + timeout
            try:
                while True:
                    if (os.fstat(output.fileno()).st_size > MAX_STDOUT_BYTES
                            or os.fstat(errors.fileno()).st_size > MAX_STDERR_BYTES):
                        raise EngineError("Przekroczono limit wyjscia narzedzia")
                    if process.poll() is not None:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise EngineError("Przekroczono limit czasu narzedzia")
                    time.sleep(min(0.02, remaining))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        if os.fstat(errors.fileno()).st_size > MAX_STDERR_BYTES:
            raise EngineError("Przekroczono limit wyjscia narzedzia")
        output.seek(0)
        raw = output.read(MAX_STDOUT_BYTES + 1)
        if len(raw) > MAX_STDOUT_BYTES:
            raise EngineError("Przekroczono limit wyjscia narzedzia")
        return process.returncode, raw.decode("utf-8-sig")


def parse_engine_output(engine: str, output: str, source: str) -> tuple[tuple[Finding, ...], bool]:
    """Waliduje i mapuje odpowiedz narzedzia na wspolny model detekcji."""
    payload = json.loads(output)
    if engine == "semgrep":
        rows = payload["results"]
        incomplete = bool(payload["errors"] or not payload["paths"]["scanned"])
    elif engine == "shellcheck":
        rows = payload
        incomplete = False
    else:
        rows = payload["items"]
        incomplete = payload["incomplete"]
    if not isinstance(rows, list) or type(incomplete) is not bool:
        raise ValueError("Invalid engine envelope")
    if not rows:
        return (), incomplete

    lines = source.split("\n")
    if engine == "esprima":
        lines = re.split("[\n\u2028\u2029]", source)
    findings = []
    seen = set()
    for row in rows[:MAX_FINDINGS]:
        line_offset = 0
        if engine == "semgrep":
            rule_id, line = row["check_id"], row["start"]["line"]
        elif engine == "shellcheck":
            code = row["code"]
            if type(code) is not int or not 1 <= code <= 99999:
                raise ValueError("Invalid ShellCheck code")
            rule_id, line = f"SC{code}", row["line"]
            line_offset = 1  # The trusted ShellCheck header occupies the first line.
            severity = SHELLCHECK_LEVELS[row["level"]]
            message = row["message"]
            if not isinstance(message, str):
                raise ValueError("Invalid ShellCheck message")
            title = message[:240]
            description = f"Diagnostyka statyczna ShellCheck ({rule_id})."
            incomplete |= row["level"] == "error"
        else:
            rule_id, line = row["id"], row["line"]
        if type(line) is not int:
            raise ValueError("Invalid engine line")
        if engine != "shellcheck":
            title, severity, description = RULE_DETAILS[rule_id]
        line = min(max(1, line - line_offset), len(lines))
        if (rule_id, line) not in seen:
            seen.add((rule_id, line))
            excerpt = (
                "Sygnatura dopasowana w calym pliku"
                if engine == "yara"
                else " ".join(lines[line - 1][:360].split())[:180]
            )
            findings.append(Finding(rule_id, title, severity, description, line, excerpt, (engine,)))
    return tuple(findings), incomplete or len(rows) > MAX_FINDINGS


def scan_engines(
    text: str, raw: bytes, language: str, output_dir: Path, representation: str,
) -> tuple[tuple[Finding, ...], tuple[EngineRun, ...]]:
    """Zbiera detekcje i stan kazdego silnika dla jednej reprezentacji skryptu."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    data = normalized.encode("utf-8")
    findings = []
    runs = []
    for engine in ENGINES_BY_LANGUAGE[language]:
        input_data = raw if engine == "yara" else data
        status, detail = "ok", ""
        try:
            command = engine_command(engine)
            if command is None:
                status, detail = "unavailable", "Nie znaleziono narzedzia w PATH"
            elif len(input_data) > MAX_INPUT_BYTES:
                status, detail = "skipped", "Dane przekraczaja limit 5 MB silnika"
            elif engine == "powershell-parser" and POWERSHELL_DIRECTIVE.search(normalized):
                status, detail = "skipped", "Mozliwa dyrektywa wymagajaca odczytu zasobow"
            else:
                if engine == "shellcheck":
                    cleaned = SHELLCHECK_DIRECTIVE.sub("# scanner", normalized)
                    if cleaned.startswith("#!"):
                        cleaned = "# " + cleaned[2:]
                    input_data = (SHELLCHECK_HEADER + cleaned).encode("utf-8")
                output_dir.mkdir(parents=True, exist_ok=True)
                with engine_temp_directory(output_dir.resolve(), ".scan-") as directory:
                    if engine == "semgrep":
                        target = SEMGREP_TARGETS[language]
                        (directory / target).write_bytes(input_data)
                        (directory / "rules.yml").write_text(json.dumps(SEMGREP_RULES), encoding="utf-8")
                        command.append(target)
                        input_data = b""
                    code, response = run_engine(command, directory, input_data)
                    if code == PACKAGE_UNAVAILABLE and engine in {"yara", "esprima"}:
                        status, detail = "unavailable", "Brak pakietu w srodowisku Python"
                    elif code != 0 and not (engine == "shellcheck" and code == 1):
                        raise EngineError(f"Narzedzie zakonczylo prace z kodem {code}")
                    else:
                        detected, incomplete = parse_engine_output(engine, response, normalized)
                        findings.extend(detected)
                        if incomplete:
                            status, detail = "partial", "Blad skladni, pominiety plik lub limit detekcji"
        except EngineError as error:
            status, detail = "error", str(error)
        except OSError:
            status, detail = "error", "Nie mozna przygotowac katalogu lub uruchomic narzedzia"
        except (ValueError, KeyError, TypeError, RecursionError):
            status, detail = "error", "Nieprawidlowa odpowiedz narzedzia"
        runs.append(EngineRun(engine, representation, status, detail))
    return tuple(findings), tuple(runs)
