"""Backward compatibility for proof-era VM anchors."""

from types import SimpleNamespace

from _blackbox_loader import load_blackbox


cli = load_blackbox("cli")
constants = load_blackbox("constants")
quads = load_blackbox("quads")
ruleset = load_blackbox("ruleset")


def _row(identifier, subject=None, **fields):
    row = {"identifier": identifier,
           "threat": subject if subject is not None else f"urn:guardian:threat:{identifier}"}
    row.update(fields)
    return row


def _proof_for(rows):
    hashes = quads.anchor_hashes_from_rows(rows)
    root = quads.anchor_root(hashes.items())
    return {"root": root, "members": set(hashes)}


class TestAnchorHash:
    def test_ignores_key_order_and_extra_fields(self):
        a = quads.threat_anchor_hash({"identifier": "dep:npm:evil@1.0.0", "severity": "critical", "name": "evil"})
        b = quads.threat_anchor_hash({"name": "evil", "severity": "critical", "identifier": "dep:npm:evil@1.0.0", "unrelated": "x"})
        assert a == b

    def test_detection_field_change_breaks_hash(self):
        base = {"identifier": "injection:abc", "pattern": "rm -rf", "severity": "high"}
        assert quads.threat_anchor_hash(base) != quads.threat_anchor_hash({**base, "severity": "low"})
        assert quads.threat_anchor_hash(base) != quads.threat_anchor_hash({**base, "pattern": "sudo"})

    def test_duplicate_rows_converge_deterministically(self):
        rows = [
            {"identifier": "dep:npm:a@1", "severity": "low"},
            {"identifier": "dep:npm:a@1", "severity": "high"},
        ]
        assert quads.anchor_hashes_from_rows(rows) == quads.anchor_hashes_from_rows(list(reversed(rows)))

    def test_root_is_order_independent(self):
        pairs = [("a", "h1"), ("b", "h2"), ("c", "h3")]
        assert quads.anchor_root(pairs) == quads.anchor_root(reversed(pairs))


class TestVerification:
    def test_full_batch_verifies(self):
        rows = [
            _row("dep:npm:evil@1.0.0", severity="critical", name="evil"),
            _row("injection:abc", severity="high", pattern="ignore previous"),
        ]
        proofs = {"urn:guardian:proof:x": _proof_for(rows)}
        assert ruleset.verified_identifiers(rows, proofs) == {"dep:npm:evil@1.0.0", "injection:abc"}

    def test_tampered_row_invalidates_whole_batch(self):
        rows = [
            _row("dep:npm:evil@1.0.0", severity="critical"),
            _row("injection:abc", severity="high", pattern="ignore previous"),
        ]
        proofs = {"urn:guardian:proof:x": _proof_for(rows)}
        rows[0]["severity"] = "low"  # downgraded after anchoring
        assert ruleset.verified_identifiers(rows, proofs) == set()

    def test_missing_member_invalidates_batch(self):
        rows = [
            _row("dep:npm:evil@1.0.0", severity="critical"),
            _row("injection:abc", severity="high", pattern="ignore previous"),
        ]
        proofs = {"urn:guardian:proof:x": _proof_for(rows)}
        assert ruleset.verified_identifiers(rows[:1], proofs) == set()

    def test_report_subject_rows_never_verify(self):
        rows = [_row("dep:npm:evil@1.0.0", subject="urn:guardian:report:0xabc:123", severity="critical")]
        proofs = {"urn:guardian:proof:x": _proof_for([_row("dep:npm:evil@1.0.0", severity="critical")])}
        assert ruleset.verified_identifiers(rows, proofs) == set()

    def test_report_row_cannot_shadow_threat_row(self):
        threat = _row("dep:npm:evil@1.0.0", severity="critical", name="evil")
        report = _row("dep:npm:evil@1.0.0", subject="urn:guardian:report:0xabc:123",
                      severity="low", name="report noise")
        proofs = {"urn:guardian:proof:x": _proof_for([threat])}
        assert ruleset.verified_identifiers([report, threat], proofs) == {"dep:npm:evil@1.0.0"}

    def test_independent_batches_verify_independently(self):
        good = [_row("dep:npm:a@1", severity="high")]
        bad = [_row("dep:npm:b@1", severity="high")]
        proofs = {
            "urn:guardian:proof:good": _proof_for(good),
            "urn:guardian:proof:bad": _proof_for(bad),
        }
        bad[0]["severity"] = "low"
        assert ruleset.verified_identifiers(good + bad, proofs) == {"dep:npm:a@1"}

    def test_sparql_json_binding_shape(self):
        rows = [{
            "threat": {"type": "uri", "value": "urn:guardian:threat:dep-npm-a-1"},
            "identifier": {"type": "literal", "value": "dep:npm:a@1"},
            "severity": {"type": "literal", "value": "high"},
        }]
        plain = [{"identifier": "dep:npm:a@1", "severity": "high"}]
        proofs = {"urn:guardian:proof:x": _proof_for(plain)}
        assert ruleset.verified_identifiers(rows, proofs) == {"dep:npm:a@1"}

    def test_verified_rows_reach_public_tier(self):
        rows = [_row("dep:npm:evil@1.0.0", severity="critical", name="evil")]
        verified = ruleset.verified_identifiers(rows, {"p": _proof_for(rows)})
        tagged = [(r, "public" if r["identifier"] in verified else "community") for r in rows]
        rs = ruleset.build_from_rows(tagged)
        rule = next(iter(rs.dependency.values()))
        assert rule["source"] == "public"


class TestDualFormat:
    """Detection supports current full VM threats plus legacy proof-era data."""

    def test_full_format_vm_threat_is_public(self):
        # A node with current full-threat KAs on VM: the VM tier yields threat
        # rows directly, tagged public — no proof needed.
        vm_rows = [{"identifier": "dep:npm:legacy@1.0.0", "severity": "critical", "name": "legacy"}]
        rs = ruleset.build_from_rows([(r, "public") for r in vm_rows])
        assert next(iter(rs.dependency.values()))["source"] == "public"

    def test_legacy_format_swm_plus_proof_is_public(self):
        swm = [_row("dep:npm:modern@2.0.0", severity="critical", name="modern")]
        verified = ruleset.verified_identifiers(swm, {"p": _proof_for(swm)})
        rs = ruleset.build_from_rows(
            [(r, "public" if r["identifier"] in verified else "community") for r in swm]
        )
        assert next(iter(rs.dependency.values()))["source"] == "public"

    def test_both_formats_coexist_in_one_ruleset(self):
        # Full threat from VM + legacy threat from SWM+proof, merged.
        vm = [{"identifier": "dep:npm:legacy@1.0.0", "severity": "high", "name": "legacy"}]
        swm = [_row("dep:npm:modern@2.0.0", severity="high", name="modern")]
        verified = ruleset.verified_identifiers(swm, {"p": _proof_for(swm)})
        tagged = [(r, "public") for r in vm] + [
            (r, "public" if r["identifier"] in verified else "community") for r in swm
        ]
        rs = ruleset.build_from_rows(tagged)
        by_id = {rule["identifier"]: rule for rule in rs.dependency.values()}
        assert by_id["dep:npm:legacy@1.0.0"]["source"] == "public"
        assert by_id["dep:npm:modern@2.0.0"]["source"] == "public"
