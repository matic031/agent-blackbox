"""Make ``tests/plugins`` importable for shared helpers (e.g. ``_blackbox_loader``)."""

import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
