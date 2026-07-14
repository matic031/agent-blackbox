#!/usr/bin/env python3
"""Refresh the installed Blackbox plugin in every local Hermes home.

WHY THIS EXISTS: `hermes` does not run the plugin from this repo — `blackbox
attach` copies it into each agent home (``~/.hermes/plugins/blackbox/``) and
runs *that* copy. `attach` only re-copies on a version bump, and its dev-mtime
check can't refresh the very home it's running from. So an in-place edit to
``plugins/blackbox/`` has NO effect on `hermes` until you re-sync.

Run this after ANY change under ``plugins/blackbox/``:

    venv/bin/python scripts/sync_blackbox_plugin.py

(OpenClaw uses the separate JS plugin in ``integrations/openclaw/`` — not
refreshed here.)
"""
from pathlib import Path

import plugins.blackbox as g
from plugins.blackbox import attach


def main() -> int:
    src = Path(g.__file__).parent
    homes = attach.discover_hermes_homes()
    if not homes:
        print("No Hermes homes found (nothing attached yet).")
        return 0
    for home in homes:
        dest = home / "plugins" / "blackbox"
        if not dest.exists():
            continue  # blackbox isn't installed in this home; `attach` handles that
        attach._copy_plugin_tree(src, dest)
        print(f"synced → {dest}")
    print(f"\nRefreshed the plugin from {src}. Restart any running agent to pick it up.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
