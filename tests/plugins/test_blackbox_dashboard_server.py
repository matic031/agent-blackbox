from _blackbox_loader import load_blackbox


server = load_blackbox("dashboard.server")
sync_state = load_blackbox("sync_state")


def test_sync_state_rejects_abandoned_running_process(tmp_path, monkeypatch):
    state_path = tmp_path / "authoritative-sync.json"
    state_path.write_text(
        '{"status":"running","pid":99999999,"updated_at":9999999999}',
        encoding="utf-8",
    )
    monkeypatch.setattr(sync_state, "_path", lambda: state_path)
    monkeypatch.setattr(sync_state, "_pid_is_alive", lambda _pid: False)

    state = sync_state.read()

    assert state["status"] == "failed"
    assert state["error"] == "authoritative sync process exited"


def test_graph_sync_state_treats_authoritatively_settled_zero_as_ready():
    assert server._graph_sync_state(0, True, "running", settled=True) == "ready"


def test_daemon_connection_hint_prefers_encryption_profile_blocker(tmp_path):
    cg_id = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox"
    daemon_log = tmp_path / "daemon.log"
    daemon_log.write_text(
        "\n".join(
            [
                '[2026-07-14T07:29:40.621Z] Network isolation: denying outbound relayed connection relay=Gq6hB57M remote=kEvwZxiU',
                f'2026-07-14 07:30:39 system abc [DKGAgent] Stored pending join request from 0x0665 for "{cg_id}"',
                f'2026-07-14 07:30:39 system def [DKGAgent] PROTOCOL_JOIN_REQUEST from Y3YiGPAM for "{cg_id}": auto-approval deferred for 0x0665 — workspace encryption profile is not available yet [WARN]',
            ]
        ),
        encoding="utf-8",
    )

    hint = server._daemon_connection_hint(str(tmp_path), cg_id)

    assert hint["state"] == "pending-encryption-profile"
    assert hint["error"] == "workspace encryption profile is not available yet"
    assert "auto-approval deferred" in hint["evidence"]


def test_daemon_connection_hint_reports_malformed_sync_envelope(tmp_path):
    cg_id = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox"
    daemon_log = tmp_path / "daemon.log"
    daemon_log.write_text(
        f'2026-07-14 07:29:23 sync xyz [DKGAgent] Denied sync request for "{cg_id}": malformed or mismatched envelope (requesterPeer=n/a targetPeer=n/a remotePeer=12D3...) [WARN]\n',
        encoding="utf-8",
    )

    hint = server._daemon_connection_hint(str(tmp_path), cg_id)

    assert hint["state"] == "sync-envelope-error"
    assert hint["error"] == "peer sent a malformed or mismatched sync envelope"
    assert "Denied sync request" in hint["evidence"]


def test_sync_activity_reports_exact_public_reconciliation_progress():
    activity = server._sync_activity(
        public=10_000,
        community=11_000,
        node_reachable=True,
        catchup={"status": "done"},
        connection={"state": "syncing", "updated_at": 200.0},
        transfer={
            "status": "running",
            "phase": "reconciling-public-memory",
            "started_at": 100.0,
            "updated_at": 190.0,
            "public_entries": 10_000,
            "expected_public_entries": 25_000,
        },
    )

    assert activity["status"] == "running"
    assert activity["phase"] == "reconciling-public-memory"
    assert activity["current"] == 10_000
    assert activity["expected"] == 25_000
    assert activity["percent"] == activity["current"] / activity["expected"] * 100
    assert activity["indeterminate"] is False


def test_sync_activity_keeps_atomic_catchup_indeterminate():
    activity = server._sync_activity(
        public=2_000,
        community=11_000,
        node_reachable=True,
        catchup={"status": "running", "startedAt": "2026-07-14T08:00:00Z"},
        connection={"state": "syncing", "updated_at": 200.0},
        transfer={},
    )

    assert activity["status"] == "running"
    assert activity["phase"] == "network-catchup"
    assert activity["started_at"] == "2026-07-14T08:00:00Z"
    assert activity["percent"] is None
    assert activity["indeterminate"] is True


def test_sync_activity_surfaces_private_graph_wait_state():
    activity = server._sync_activity(
        public=0,
        community=0,
        node_reachable=True,
        catchup={},
        connection={"state": "pending-approval", "updated_at": 123.0},
        transfer={},
    )

    assert activity["status"] == "waiting"
    assert activity["phase"] == "pending-approval"
    assert activity["label"] == "Waiting for curator approval"


def test_sync_activity_does_not_hide_failure_behind_stale_syncing_state():
    activity = server._sync_activity(
        public=2_000,
        community=0,
        node_reachable=True,
        catchup={"status": "failed", "error": "protocol negotiation failed"},
        connection={"state": "syncing", "updated_at": 123.0},
        transfer={},
    )

    assert activity["status"] == "failed"
    assert activity["detail"] == "protocol negotiation failed"


def test_sync_activity_prefers_completed_authoritative_transfer_over_stale_connection():
    activity = server._sync_activity(
        public=25_000,
        community=0,
        node_reachable=True,
        catchup={"status": "unreachable"},
        connection={"state": "syncing", "updated_at": 200.0},
        transfer={
            "status": "done",
            "phase": "complete",
            "started_at": 100.0,
            "updated_at": 190.0,
            "public_entries": 25_000,
            "community_entries": 0,
            "expected_public_entries": 25_000,
        },
    )

    assert activity == {
        "status": "ready",
        "phase": "complete",
        "label": "Threat graphs are ready",
        "detail": "25,000 public and 0 community threats are queryable.",
        "started_at": 100.0,
        "updated_at": 190.0,
        "current": 25_000,
        "expected": 25_000,
        "percent": 100.0,
        "indeterminate": False,
    }


def test_sync_activity_keeps_new_catchup_visible_after_authoritative_transfer():
    activity = server._sync_activity(
        public=25_000,
        community=0,
        node_reachable=True,
        catchup={"status": "running", "startedAt": 300.0},
        connection={"state": "syncing", "updated_at": 300.0},
        transfer={"status": "done", "phase": "complete", "updated_at": 190.0},
    )

    assert activity["status"] == "running"
    assert activity["phase"] == "network-catchup"
