"""Shared importlib loader for the bundled Blackbox plugin.

Loads ``plugins/blackbox`` as the package ``hermes_plugins.blackbox`` (the same
scheme the pre-existing Blackbox test uses) so the module's relative imports
(``from . import ...``) resolve. Submodules are then importable normally.
"""

import importlib
import importlib.util
import sys
import types
from pathlib import Path

_PKG = "hermes_plugins.blackbox"
_PLUGIN_DIR = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"


def _ensure_package():
    if _PKG in sys.modules:
        return sys.modules[_PKG]
    if "hermes_plugins" not in sys.modules:
        ns = types.ModuleType("hermes_plugins")
        ns.__path__ = []
        sys.modules["hermes_plugins"] = ns
    spec = importlib.util.spec_from_file_location(
        _PKG,
        _PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(_PLUGIN_DIR)],
    )
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = _PKG
    mod.__path__ = [str(_PLUGIN_DIR)]
    sys.modules[_PKG] = mod
    spec.loader.exec_module(mod)
    return mod


def load_blackbox(submodule: str = ""):
    """Return the blackbox package, or a named submodule (e.g. ``"quads"``)."""
    _ensure_package()
    if not submodule:
        return sys.modules[_PKG]
    return importlib.import_module(f"{_PKG}.{submodule}")
