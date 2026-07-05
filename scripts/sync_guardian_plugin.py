#!/usr/bin/env python3
"""Refresh the installed Guardian plugin in every local Hermes home.

WHY THIS EXISTS: `hermes` does not run the plugin from this repo — `guardian
attach` copies it into each agent home (``~/.hermes/plugins/guardian/``) and
runs *that* copy. `attach` only re-copies on a version bump, and its dev-mtime
check can't refresh the very home it's running from. So an in-place edit to
``plugins/guardian/`` has NO effect on `hermes` until you re-sync.

Run this after ANY change under ``plugins/guardian/``:

    venv/bin/python scripts/sync_guardian_plugin.py

(OpenClaw uses the separate JS plugin in ``integrations/openclaw/`` — not
refreshed here.)
"""
from pathlib import Path

import plugins.guardian as g
from plugins.guardian import attach


def main() -> int:
    src = Path(g.__file__).parent
    homes = attach.discover_hermes_homes()
    if not homes:
        print("No Hermes homes found (nothing attached yet).")
        return 0
    for home in homes:
        dest = home / "plugins" / "guardian"
        if not dest.exists():
            continue  # guardian isn't installed in this home; `attach` handles that
        attach._copy_plugin_tree(src, dest)
        print(f"synced → {dest}")
    print(f"\nRefreshed the plugin from {src}. Restart any running agent to pick it up.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
