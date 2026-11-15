"""Kontrolowane bledy domenowe analizatora."""


class AnalysisError(Exception):
    """Bazowy blad, ktory mozna bezpiecznie pokazac uzytkownikowi CLI."""


class InputFileError(AnalysisError):
    """Plik wejsciowy jest niedostepny, za duzy albo nie jest tekstem."""


class UnsupportedLanguageError(AnalysisError):
    """Nie udalo sie rozpoznac obslugiwanego jezyka skryptowego."""


class ConfigurationError(AnalysisError):
    """Konfiguracja analizy jest niespojna albo niebezpieczna."""


class ReportError(AnalysisError):
    """Nie udalo sie bezpiecznie zapisac raportu."""


class MonitorError(AnalysisError):
    """Nie udalo sie pobrac albo zapisac danych monitora systemowego."""

