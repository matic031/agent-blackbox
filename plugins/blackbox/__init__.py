"""Agent Blackbox — graph-driven agent security for Hermes.

Blackbox syncs a threat ruleset from the local OriginTrail DKG node (verified
threats from the public graph + the node's local graph) and matches every tool
call and model request against it. In audit mode (default) it records findings
and shares anonymized sightings; in block mode it refuses tool calls that match
a threat at or above the configured severity.

This module is intentionally thin: it wires the five hooks and the ``blackbox``
CLI, delegating all behaviour to the submodules (:mod:`hooks`, :mod:`cli`).
"""

from __future__ import annotations

from . import cli as _cli
from . import hooks as _hooks
from .constants import __version__

__all__ = ["register", "__version__"]


def register(ctx) -> None:
    """Wire Blackbox's hooks and CLI into the hermes plugin context."""
    ctx.register_hook("pre_tool_call", _hooks.on_pre_tool_call)
    ctx.register_hook("post_tool_call", _hooks.on_post_tool_call)
    ctx.register_hook("pre_api_request", _hooks.on_pre_api_request)
    ctx.register_hook("on_session_start", _hooks.on_session_start)
    ctx.register_hook("on_session_end", _hooks.on_session_end)
    ctx.register_cli_command(
        "blackbox",
        "Agent Blackbox — threat-graph-driven agent security",
        _cli.setup_cli,
    )
