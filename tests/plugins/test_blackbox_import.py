"""Tests for the curator catalog import: bumblebee fan-out + legacy formats."""

from types import SimpleNamespace

from _blackbox_loader import load_blackbox


cli = load_blackbox("cli")
quads = load_blackbox("quads")
constants = load_blackbox("constants")


def test_bumblebee_normalizes_double_at_and_tags_malware():
    # Bumblebee ships npm scopes with a malformed double-@ (``@@antv/a8``).
    # It must collapse to a single @ so the seeded id matches a real install,
    # and be tagged malware (compromised packages block).
    catalog = {
        "entries": [{
            "id": "socket-2026-05-19-antv", "name": "@@antv/a8 (compromised)",
            "ecosystem": "npm", "package": "@@antv/a8", "versions": ["0.1.1"],
            "severity": "critical", "source": "https://socket.dev/blog/antv-packages-compromised",
        }]
    }
    entries = cli._flatten_catalog(catalog, forced_type=None)
    assert len(entries) == 1
    category, ident, fields = cli._entry_to_threat(entries[0])
    assert ident == "dep:npm:@antv/a8@0.1.1"                       # @@ collapsed to @
    assert ident == quads.dependency_identifier("npm", "@antv/a8", "0.1.1")  # matches real install
    assert fields["kind"] == "malware"


def test_seed_entries_dedups_and_dry_run_spends_nothing():
    # Two spellings of one npm package (npm lowercases names) + a distinct one,
    # plus one already in the ledger. Dry-run must publish nothing and report the
    # de-duplicated count so a curator sees the TRAC bill before spending it.
    entries = [
        {"type": "dependency", "ecosystem": "npm", "name": "evil", "version": "1.0.0"},
        {"type": "dependency", "ecosystem": "npm", "name": "EVIL", "version": "1.0.0"},  # same id
        {"type": "dependency", "ecosystem": "npm", "name": "evil", "version": "2.0.0"},
        {"type": "dependency", "ecosystem": "npm", "name": "seen", "version": "9.0.0"},  # in ledger
    ]
    already = {"dep:npm:seen@9.0.0"}
    # A real seed publishes on-chain: dry-run previews exactly which ids would be
    # published (the ledger/TRAC set) without spending anything.
    seeded, skipped, errors, new_ids, attempted = cli._seed_entries(
        None, None, entries, publish=True, already=already, dry_run=True, source="UnitTest"
    )
    assert (seeded, skipped, errors) == (2, 2, 0)
    assert attempted == 2
    assert new_ids == ["dep:npm:evil@1.0.0", "dep:npm:evil@2.0.0"]

    # A --no-publish (SWM-only) run records NOTHING in the ledger, so it can
    # never make a later real publish skip these ids as "already published".
    _, _, _, no_pub_ids, attempted = cli._seed_entries(
        None, None, entries, publish=False, already={"dep:npm:seen@9.0.0"}, dry_run=True, source="UnitTest"
    )
    assert attempted == 2
    assert no_pub_ids == []


def test_seed_entries_limit_caps_new_publishes_for_batching():
    # Batch seeding on mainnet costs real TRAC, so --limit stops after N NEW
    # publishes — a curator verifies each batch before paying for the next.
    # Duplicates don't count toward the limit; untouched entries are left for a
    # later run (the ledger resumes them, so it never double-pays).
    entries = [
        {"type": "dependency", "ecosystem": "npm", "name": "seen", "version": "1.0.0"},  # dup
        {"type": "dependency", "ecosystem": "npm", "name": "a", "version": "1.0.0"},
        {"type": "dependency", "ecosystem": "npm", "name": "b", "version": "1.0.0"},
        {"type": "dependency", "ecosystem": "npm", "name": "c", "version": "1.0.0"},  # past the limit
    ]
    already = {"dep:npm:seen@1.0.0"}
    seeded, skipped, errors, new_ids, attempted = cli._seed_entries(
        None, None, entries, publish=True, already=already, dry_run=True, limit=2, source="UnitTest"
    )
    assert (seeded, skipped, errors) == (2, 1, 0)
    assert attempted == 2
    assert new_ids == ["dep:npm:a@1.0.0", "dep:npm:b@1.0.0"]
    # 'c' was never processed, so a follow-up run picks it up next.
    assert "dep:npm:c@1.0.0" not in already


def test_seed_entries_limit_counts_failed_publish_attempts(capsys):
    class FailingClient:
        def share_knowledge_asset(self, cg_id, name, q):
            raise cli.DkgError("share failed")

    entries = [
        {"type": "dependency", "ecosystem": "npm", "name": "a", "version": "1.0.0", "source": "UnitTest"},
        {"type": "dependency", "ecosystem": "npm", "name": "b", "version": "1.0.0", "source": "UnitTest"},
    ]
    already = set()
    seeded, skipped, errors, new_ids, attempted = cli._seed_entries(
        FailingClient(),
        SimpleNamespace(context_graph_id="cg/test"),
        entries,
        publish=True,
        already=already,
        dry_run=False,
        limit=1,
    )

    assert (seeded, skipped, errors, attempted) == (0, 0, 1, 1)
    assert new_ids == []
    assert "dep:npm:a@1.0.0" in already
    assert "dep:npm:b@1.0.0" not in already
    assert "failed to seed dep:npm:a@1.0.0" in capsys.readouterr().out


def test_seed_entries_requires_source_provenance():
    entries = [
        {"type": "dependency", "ecosystem": "npm", "name": "evil", "version": "1.0.0"},
    ]
    seeded, skipped, errors, new_ids, attempted = cli._seed_entries(
        None, None, entries, publish=True, already=set(), dry_run=True
    )
    assert (seeded, skipped, errors) == (0, 0, 1)
    assert attempted == 0
    assert new_ids == []


def test_seed_entries_splits_full_swm_from_minimal_vm(monkeypatch):
    class FakeClient:
        def __init__(self):
            self.shares = []
            self.publishes = []

        def share_knowledge_asset(self, cg_id, name, q):
            self.shares.append((cg_id, name, q))
            return {"shareOperationId": "share-ok"}

        def publish_async_and_wait(self, cg_id, name, epochs=1, timeout_s=600, poll_s=5):
            self.publishes.append((cg_id, name, epochs, timeout_s, poll_s))
            return {"status": "finalized"}

    ledger = []
    monkeypatch.setattr(cli, "_append_seeded_ledger", lambda ids: ledger.extend(ids))
    client = FakeClient()
    cfg = SimpleNamespace(context_graph_id="cg/test")
    entries = [{
        "type": "dependency",
        "ecosystem": "npm",
        "name": "evil",
        "version": "1.0.0",
        "severity": "critical",
        "description": "rich private context stays in SWM",
        "source": "UnitTest",
        "references": ["https://example.test/advisory"],
    }]

    seeded, skipped, errors, new_ids, attempted = cli._seed_entries(
        client,
        cfg,
        entries,
        publish=True,
        already=set(),
        dry_run=False,
        epochs=3,
        publish_timeout=12,
        publish_poll_interval=2,
    )

    assert (seeded, skipped, errors) == (1, 0, 0)
    assert attempted == 1
    assert new_ids == ["dep:npm:evil@1.0.0"]
    assert ledger == ["dep:npm:evil@1.0.0"]
    assert [name for _cg, name, _q in client.shares] == [
        "candidate-dep-npm-evil-1.0.0",
        "threat-vm-dep-npm-evil-1.0.0",
    ]
    assert client.publishes == [("cg/test", "threat-vm-dep-npm-evil-1.0.0", 3, 12, 2)]

    full_preds = {t["predicate"] for _cg, _name, q in client.shares[:1] for t in q}
    vm_preds = {t["predicate"] for _cg, _name, q in client.shares[1:] for t in q}
    assert constants.SCHEMA_DESCRIPTION_PRED in full_preds
    assert constants.SCHEMA_DESCRIPTION_PRED not in vm_preds
    assert constants.IDENTIFIER_PRED in vm_preds
    assert constants.SEVERITY_PRED in vm_preds
    assert constants.SOURCE_PRED in vm_preds
    assert constants.REFERENCE_PRED in vm_preds
    assert constants.PACKAGE_NAME_PRED in vm_preds
    assert constants.PACKAGE_VERSION_PRED in vm_preds
    assert constants.PACKAGE_ECOSYSTEM_PRED in vm_preds


def test_seed_entries_no_publish_only_shares_full_swm(monkeypatch):
    class FakeClient:
        def __init__(self):
            self.shares = []
            self.publishes = []

        def share_knowledge_asset(self, cg_id, name, q):
            self.shares.append((cg_id, name, q))
            return {}

        def publish_async_and_wait(self, *args, **kwargs):  # pragma: no cover - should not run
            self.publishes.append((args, kwargs))
            return {}

    ledger = []
    monkeypatch.setattr(cli, "_append_seeded_ledger", lambda ids: ledger.extend(ids))
    client = FakeClient()
    seeded, skipped, errors, new_ids, attempted = cli._seed_entries(
        client,
        SimpleNamespace(context_graph_id="cg/test"),
        [{"type": "dependency", "ecosystem": "npm", "name": "evil", "version": "2.0.0", "source": "UnitTest"}],
        publish=False,
        already=set(),
        dry_run=False,
    )
    assert (seeded, skipped, errors) == (1, 0, 0)
    assert attempted == 1
    assert new_ids == []
    assert ledger == []
    assert [name for _cg, name, _q in client.shares] == ["candidate-dep-npm-evil-2.0.0"]
    assert client.publishes == []


def test_setup_graph_seeds_local_agent_allowlist(monkeypatch):
    calls = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def chain_info(self):
            return {"chain_id": 8453, "network": "mainnet-base", "is_mainnet": True, "is_testnet": False}

        def agent_identity(self):
            return {"agentAddress": "0x0000000000000000000000000000000000000001"}

        def create_context_graph(self, *args, **kwargs):
            calls.append(("create", args, kwargs))
            return {}

        def list_context_graph_agents(self, cg_id):
            calls.append(("list_agents", cg_id))
            return []

        def add_context_graph_agent(self, cg_id, agent):
            calls.append(("add_agent", cg_id, agent))
            return {}

        def register_context_graph(self, *args, **kwargs):
            calls.append(("register", args, kwargs))
            return {}

    monkeypatch.setattr(cli, "DkgClient", FakeClient)
    monkeypatch.setattr(
        cli,
        "load_blackbox_config",
        lambda: SimpleNamespace(
            dkg_url="http://node",
            dkg_home="/tmp/dkg",
            context_graph_id="umanitek/blackbox-threats-staging",
        ),
    )

    assert cli._cmd_setup_graph(SimpleNamespace(network="base")) == 0
    create = next(call for call in calls if call[0] == "create")
    assert create[2]["access_policy"] == 1
    assert create[2]["allowed_agents"] == ["0x0000000000000000000000000000000000000001"]
    assert ("add_agent", "umanitek/blackbox-threats-staging", "0x0000000000000000000000000000000000000001") in calls
    register = next(call for call in calls if call[0] == "register")
    assert register[2] == {"access_policy": 1, "publish_policy": 0}


# A small bumblebee-shaped catalog: one package, three malicious versions.
BUMBLEBEE = {
    "schema_version": "0.1.0",
    "_comment": "Malicious node-ipc releases from the 2026-05 credential stealer compromise.",
    "entries": [
        {
            "id": "socket-2026-05-14-npm-node-ipc-credential-stealer",
            "name": "node-ipc (May 2026 credential stealer compromise)",
            "ecosystem": "npm",
            "package": "node-ipc",
            "versions": ["9.1.6", "9.2.3", "12.0.1"],
            "severity": "critical",
            "source": "https://socket.dev/blog/node-ipc-package-compromised",
            "indicators": {"process_marker": "__ntw=1"},
        }
    ],
}


def test_flatten_bumblebee_fans_out_per_version():
    entries = cli._flatten_catalog(BUMBLEBEE, forced_type=None)
    assert len(entries) == 3  # one per version
    assert all(e["type"] == "dependency" for e in entries)
    versions = {e["version"] for e in entries}
    assert versions == {"9.1.6", "9.2.3", "12.0.1"}
    for e in entries:
        assert e["ecosystem"] == "npm"
        assert e["package"] == "node-ipc"
        assert e["severity"] == "critical"
        assert e["advisoryId"] == "socket-2026-05-14-npm-node-ipc-credential-stealer"
        assert e["references"] == ["https://socket.dev/blog/node-ipc-package-compromised"]
        assert "node-ipc" in e["description"]


def test_bumblebee_entries_produce_correct_dep_identifiers():
    entries = cli._flatten_catalog(BUMBLEBEE, forced_type=None)
    idents = set()
    for e in entries:
        category, ident, fields = cli._entry_to_threat(e)
        assert category == "dependency"
        idents.add(ident)
        # package name resolves to the package, NOT the display title.
        assert fields["package_name"] == "node-ipc"
        assert fields["ecosystem"] == "npm"
        assert fields["severity"] == "critical"
        assert fields["advisory_id"] == "socket-2026-05-14-npm-node-ipc-credential-stealer"
    assert idents == {
        "dep:npm:node-ipc@9.1.6",
        "dep:npm:node-ipc@9.2.3",
        "dep:npm:node-ipc@12.0.1",
    }


def test_bumblebee_detection_true_only_for_entries_shape():
    assert cli._is_bumblebee_catalog(BUMBLEBEE) is True
    # A generic {threats:[...]} catalog is NOT bumblebee.
    assert cli._is_bumblebee_catalog({"threats": [{"type": "injection"}]}) is False
    # An entries list without package+versions is not bumblebee either.
    assert cli._is_bumblebee_catalog({"entries": [{"id": "x"}]}) is False


def test_legacy_threats_format_still_works():
    catalog = {
        "threats": [
            {
                "type": "dependency",
                "ecosystem": "pypi",
                "name": "requests",
                "version": "2.0.0",
                "severity": "high",
            }
        ]
    }
    entries = cli._flatten_catalog(catalog, forced_type=None)
    assert len(entries) == 1
    category, ident, fields = cli._entry_to_threat(entries[0])
    assert category == "dependency"
    assert ident == "dep:pypi:requests@2.0.0"
    assert fields["package_name"] == "requests"


def test_legacy_split_format_still_works():
    catalog = {
        "dependencies": [{"ecosystem": "npm", "name": "left-pad", "version": "1.0.0"}],
        "injection": [{"pattern": "ignore previous instructions", "severity": "high"}],
    }
    entries = cli._flatten_catalog(catalog, forced_type=None)
    types = sorted(e["type"] for e in entries)
    assert types == ["dependency", "injection"]


def test_build_threat_quads_for_a_bumblebee_entry():
    entries = cli._flatten_catalog(BUMBLEBEE, forced_type=None)
    category, ident, fields = cli._entry_to_threat(entries[0])
    q = quads.build_threat_quads(
        category=category,
        identifier=ident,
        severity=fields["severity"],
        name=fields["name"],
        description=fields["description"],
        ecosystem=fields["ecosystem"],
        package_name=fields["package_name"],
        package_version=fields["package_version"],
        advisory_id=fields["advisory_id"],
        references=fields.get("references"),
    )
    subjects = {t["subject"] for t in q}
    assert subjects == {quads.threat_uri(ident)}
    preds = {t["predicate"] for t in q}
    constants = load_blackbox("constants")
    assert constants.PACKAGE_NAME_PRED in preds
    assert constants.PACKAGE_ECOSYSTEM_PRED in preds
