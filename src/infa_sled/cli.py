"""Interfejs wiersza polecen dla pasywnego analizatora."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .config import AnalysisConfig, SUPPORTED_REPORT_FORMATS
from .errors import AnalysisError, ConfigurationError
from .pipeline import analyze_and_write, analyze_file
from .reporting import render_terminal


def parse_formats(value: str) -> tuple[str, ...]:
    """Waliduje rozdzielona przecinkami liste formatow raportu."""

    formats = tuple(dict.fromkeys(item.strip().lower() for item in value.split(",") if item.strip()))
    unknown = set(formats) - SUPPORTED_REPORT_FORMATS
    if not formats or unknown:
        raise argparse.ArgumentTypeError(f"Nieprawidlowe formaty: {sorted(unknown)}")
    return formats


def build_parser() -> argparse.ArgumentParser:
    """Buduje parser CLI w jednym miejscu, aby interfejs byl testowalny."""

    parser = argparse.ArgumentParser(
        prog="infa-sled",
        description="Pasywna analiza skryptow PowerShell, JavaScript i Bash",
    )
    parser.add_argument("input", type=Path, help="plik skryptu do analizy")
    parser.add_argument("-o", "--output", type=Path, default=Path("report"))
    parser.add_argument("--formats", type=parse_formats, default=("json", "pdf"))
    parser.add_argument(
        "--mode",
        choices=("files", "terminal", "both"),
        default="both",
        help="files: zapis plikow, terminal: raport tekstowy, both: oba wyjscia",
    )
    parser.add_argument("--max-file-size", type=int, default=5_000_000)
    parser.add_argument("--connection-log", action="append", type=Path, default=[])
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

    api_key = os.environ.get(args.api_key_env) if args.reputation else None
    return AnalysisConfig(
        output_dir=args.output,
        max_file_size=args.max_file_size,
        report_formats=args.formats,
        connection_logs=tuple(args.connection_log),
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
        if args.mode == "terminal":
            result = analyze_file(args.input, config)
            outputs = ()
        else:
            result, outputs = analyze_and_write(args.input, config)
    except (AnalysisError, ConfigurationError) as error:
        print(f"Blad: {error}", file=sys.stderr)
        return 2
    if args.mode in {"terminal", "both"}:
        print(render_terminal(result), end="")
    else:
        print(
            f"Analiza zakonczona: {len(result.findings)} detekcji, "
            f"{len(result.iocs)} IOC, {len(result.connection_matches)} korelacji."
        )
    if outputs:
        print("\nZapisane pliki:")
        for path in outputs:
            print(f"  {path}")
    return 0
