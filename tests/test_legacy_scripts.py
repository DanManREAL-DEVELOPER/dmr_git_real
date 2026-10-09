"""Preserve script-style assertions and propagate their failures to pytest/CI."""
from pathlib import Path
import subprocess
import sys

import pytest

from conftest import collect_ignore


@pytest.mark.parametrize("script", collect_ignore)
def test_legacy_script(script):
    path = Path(__file__).with_name(script)
    result = subprocess.run([sys.executable, str(path)], capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
