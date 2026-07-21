"""Read durable-sync progress emitted by the managed DKG daemon."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict


_DURABLE_PROGRESS_RE = re.compile(
    r'Rootless durable progress for "(?P<graph>[^"]+)".*?'
    r'safe offset (?P<previous>\d+)->(?P<current>\d+) of (?P<expected>\d+)'
    r' \(raw (?P<raw>\d+)\)'
)


def read_durable_progress(dkg_home: str, context_graph_id: str) -> Dict[str, Any]:
    """Return the latest rootless durable-sync window for ``context_graph_id``.

    ``current_triples`` is transfer progress and may include the raw tail of an
    incomplete exact graph. ``safe_current_triples`` contains only complete,
    verified graph boundaries and is therefore the completion signal callers
    should use after a successful catch-up response.
    """
    path = Path(dkg_home) / "daemon.log"
    try:
        with path.open("rb") as handle:
            size = path.stat().st_size
            handle.seek(max(0, size - 4_000_000))
            text = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return {}

    matches = []
    for match in _DURABLE_PROGRESS_RE.finditer(text):
        if match.group("graph") != context_graph_id:
            continue
        # A previous implementation reset only on 0->0. Real bounded passes
        # begin 0->positive, so retaining earlier matches made a restarted
        # transfer look permanently 100% complete.
        if int(match.group("previous")) == 0:
            matches = []
        matches.append(match)
    if not matches:
        return {}

    expected = int(matches[-1].group("expected"))
    if expected <= 0:
        return {}
    same_manifest = [
        match for match in matches if int(match.group("expected")) == expected
    ]
    safe_current = max(int(match.group("current")) for match in same_manifest)
    raw_current = max(int(match.group("raw")) for match in same_manifest)
    safe_current = max(0, min(safe_current, expected))
    current = max(0, min(max(safe_current, raw_current), expected))
    return {
        "current_triples": current,
        "safe_current_triples": safe_current,
        "expected_triples": expected,
        "progress_percent": round((current / expected) * 100, 1),
        "snapshot_complete": safe_current >= expected,
    }

