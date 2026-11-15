"""Walidowana konfiguracja pojedynczego uruchomienia analizy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from errors import ConfigurationError

SUPPORTED_REPORT_FORMATS = frozenset({"json", "pdf"})
SUPPORTED_REPUTATION_PROVIDERS = frozenset({"virustotal", "urlhaus"})


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    output_dir: Path = Path("raport")
    max_file_size: int = 5_000_000
    report_formats: tuple[str, ...] = ("json", "pdf")
    connection_logs: tuple[Path, ...] = ()
    execution_logs: tuple[Path, ...] = ()
    system_history: bool = False
    history_hours: int = 24
    history_max_events: int = 1000
    original_script_path: str | None = None
    ntp_server: str | None = None
    reputation_provider: str | None = None
    reputation_api_key: str | None = None
    enable_network: bool = False
    request_timeout: float = 5.0

    def __post_init__(self) -> None:
        formats = tuple(dict.fromkeys(item.lower() for item in self.report_formats))
        unknown = set(formats) - SUPPORTED_REPORT_FORMATS
        if not formats or unknown:
            raise ConfigurationError(f"Nieprawidlowe formaty raportu: {sorted(unknown)}")
        if self.max_file_size <= 0:
            raise ConfigurationError("Limit rozmiaru pliku musi byc dodatni")
        if self.request_timeout <= 0:
            raise ConfigurationError("Limit czasu musi byc dodatni")
        if not 1 <= self.history_hours <= 8760:
            raise ConfigurationError("Zakres historii musi wynosic od 1 do 8760 godzin")
        if not 1 <= self.history_max_events <= 10000:
            raise ConfigurationError("Limit historii musi wynosic od 1 do 10000 zdarzen")
        if self.reputation_provider not in SUPPORTED_REPUTATION_PROVIDERS | {None}:
            raise ConfigurationError("Nieobslugiwany dostawca reputacji")
        if (self.ntp_server or self.reputation_provider) and not self.enable_network:
            raise ConfigurationError("Funkcje sieciowe wymagaja jawnego enable_network=True")
        if self.reputation_provider and not self.reputation_api_key:
            raise ConfigurationError("Wybrany dostawca reputacji wymaga klucza API")
        object.__setattr__(self, "output_dir", Path(self.output_dir))
        object.__setattr__(self, "report_formats", formats)
        object.__setattr__(self, "connection_logs", tuple(Path(path) for path in self.connection_logs))
        object.__setattr__(self, "execution_logs", tuple(Path(path) for path in self.execution_logs))
