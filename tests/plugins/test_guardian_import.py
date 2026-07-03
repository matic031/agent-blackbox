"""Tests for the curator catalog import: bumblebee fan-out + legacy formats."""

from _guardian_loader import load_guardian


cli = load_guardian("cli")
quads = load_guardian("quads")


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
    seeded, skipped, errors, new_ids = cli._seed_entries(
        None, None, entries, publish=False, already=already, dry_run=True
    )
    assert (seeded, skipped, errors) == (2, 2, 0)
    assert new_ids == ["dep:npm:evil@1.0.0", "dep:npm:evil@2.0.0"]


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
    constants = load_guardian("constants")
    assert constants.PACKAGE_NAME_PRED in preds
    assert constants.PACKAGE_ECOSYSTEM_PRED in preds
