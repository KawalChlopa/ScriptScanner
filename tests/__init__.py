"""Konfiguracja importow dla testow uruchamianych bez instalacji pakietu."""

import sys
import tempfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TEST_TEMP_ROOT = REPOSITORY_ROOT / "tmp" / "test-runtime"
TEST_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = str(TEST_TEMP_ROOT)
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
