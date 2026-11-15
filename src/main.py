"""Glowny punkt uruchomienia pasywnego analizatora."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from config import AnalysisConfig
from errors import AnalysisError, ConfigurationError
from pipeline import analyze_and_write, analyze_file
from reporting import render_terminal
from version import __version__


def build_parser() -> argparse.ArgumentParser:
    """Buduje parser CLI w jednym miejscu, aby interfejs byl testowalny."""

    parser = argparse.ArgumentParser(
        prog="infa-sled",
        description="Pasywna analiza skryptow PowerShell, JavaScript i Bash",
    )
    parser.add_argument("input", type=Path, help="plik skryptu do analizy")
    parser.add_argument("-o", "--output", type=Path, default=Path("raport"))
    parser.add_argument(
        "--mode",
        choices=("terminal", "raport"),
        default="terminal",
        help="terminal: tylko wynik na ekranie; raport: dodatkowo zapis plikow",
    )
    parser.add_argument(
        "--type",
        "--typ",
        dest="report_type",
        choices=("json", "pdf", "all"),
        help="format dla --mode raport; domyslnie: all",
    )
    parser.add_argument("--max-file-size", type=int, default=5_000_000)
    parser.add_argument("--connection-log", action="append", type=Path, default=[])
    parser.add_argument("--execution-log", action="append", type=Path, default=[],
                        help="log dowodow uruchomienia (XML/JSONL/CSV/auditd); mozna powtorzyc")
    parser.add_argument("--system-history", action="store_true",
                        help="jednorazowo odczytaj dostepne dzienniki tego komputera")
    parser.add_argument("--history-hours", type=int, default=24,
                        help="zakres odczytu systemu w godzinach (domyslnie 24)")
    parser.add_argument("--history-max-events", type=int, default=1000,
                        help="maksymalna liczba wpisow na dziennik systemowy (domyslnie 1000)")
    parser.add_argument("--original-script-path", help="oryginalna pelna sciezka badanego pliku na maszynie z logow")
    parser.add_argument("--enable-network", action="store_true")
    parser.add_argument("--ntp-server")
    parser.add_argument("--reputation", choices=("virustotal", "urlhaus"))
    parser.add_argument(
        "--api-key-env",
        default="INFA_SLED_API_KEY",
        help="nazwa zmiennej srodowiskowej z kluczem dostawcy",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def config_from_args(args: argparse.Namespace) -> AnalysisConfig:
    """Tworzy walidowana konfiguracje, nie ujawniajac klucza w argumentach procesu."""

    if args.mode == "terminal" and args.report_type is not None:
        raise ConfigurationError("Opcja --type wymaga --mode raport")
    report_formats = (
        ("json", "pdf")
        if args.report_type in {None, "all"}
        else (args.report_type,)
    )
    api_key = os.environ.get(args.api_key_env) if args.reputation else None
    return AnalysisConfig(
        output_dir=args.output,
        max_file_size=args.max_file_size,
        report_formats=report_formats,
        connection_logs=tuple(args.connection_log),
        execution_logs=tuple(args.execution_log),
        system_history=args.system_history,
        history_hours=args.history_hours,
        history_max_events=args.history_max_events,
        original_script_path=args.original_script_path,
        ntp_server=args.ntp_server,
        reputation_provider=args.reputation,
        reputation_api_key=api_key,
        enable_network=args.enable_network,
        request_timeout=args.timeout,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Uruchamia CLI i zwraca przewidywalny kod zakonczenia."""

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        config = config_from_args(args)

        print(f"Analiza pliku: {args.input}")

        def show_progress(step: int, total: int, message: str) -> None:
            print(f"  [{step}/{total}] {message}", flush=True)

        if args.mode == "raport":
            result, outputs = analyze_and_write(args.input, config, progress=show_progress)
        else:
            result = analyze_file(args.input, config, progress=show_progress)
            outputs = ()
    except (AnalysisError, ConfigurationError) as error:
        print(f"Blad: {error}", file=sys.stderr)
        return 2
    print()
    print(render_terminal(result), end="")
    if outputs:
        print("\nZapisane pliki:")
        for path in outputs:
            print(f"  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
