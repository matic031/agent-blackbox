"""Tests for the stdlib DKG HTTP client (mocked urlopen)."""

import io
import json
import urllib.error

import pytest

from _blackbox_loader import load_blackbox


dkg_client = load_blackbox("dkg_client")


class _FakeResponse:
    def __init__(self, body):
        self._body = body.encode() if isinstance(body, str) else body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _capture(monkeypatch, body='{"ok": true}'):
    """Patch urlopen to record the request and return *body*."""
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        captured["body"] = req.data.decode() if req.data else None
        captured["timeout"] = timeout
        return _FakeResponse(body)

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", fake_urlopen)
    return captured


def test_url_and_token_resolution(monkeypatch):
    monkeypatch.setenv("BLACKBOX_DKG_DAEMON_URL", "http://example:9999/")
    monkeypatch.setenv("BLACKBOX_DKG_API_TOKEN", "tok-123")
    client = dkg_client.DkgClient()
    assert client.url == "http://example:9999"  # trailing slash stripped
    assert client.token == "tok-123"


def test_blackbox_dkg_port_sets_default_url(monkeypatch):
    monkeypatch.delenv("BLACKBOX_DKG_DAEMON_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_URL", raising=False)
    monkeypatch.setenv("BLACKBOX_DKG_PORT", "9331")
    assert dkg_client.load_daemon_url() == "http://127.0.0.1:9331"


def test_generic_dkg_env_does_not_bleed_into_blackbox(monkeypatch, tmp_path):
    blackbox_home = tmp_path / "blackbox-dkg"
    blackbox_home.mkdir()
    (blackbox_home / "auth.token").write_text("# local Blackbox node token\nblackbox-token\n")
    default_dkg_home = tmp_path / "default-dkg"
    default_dkg_home.mkdir()
    (default_dkg_home / "auth.token").write_text("default-token\n")

    monkeypatch.delenv("BLACKBOX_DKG_DAEMON_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_PORT", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_API_TOKEN", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("DKG_DAEMON_URL", "http://default-node:9200/")
    monkeypatch.setenv("DKG_API_TOKEN", "default-env-token")
    monkeypatch.setenv("DKG_HOME", str(default_dkg_home))

    client = dkg_client.DkgClient(dkg_home=str(blackbox_home))
    assert client.url == dkg_client.constants.DEFAULT_DKG_URL
    assert client.token == "blackbox-token"


def test_share_knowledge_asset_payload(monkeypatch):
    cap = _capture(monkeypatch)
    client = dkg_client.DkgClient(url="http://node", token="tok")
    quads = [{"subject": "s", "predicate": "p", "object": '"o"'}]
    client.share_knowledge_asset("cg", "notes", quads)
    assert cap["url"] == "http://node/api/knowledge-assets"
    assert cap["method"] == "POST"
    body = json.loads(cap["body"])
    assert body["contextGraphId"] == "cg"
    assert body["name"] == "notes"
    assert body["quads"] == quads
    assert body["alsoShareSwm"] is True
    # Auth header present.
    assert any(v == "Bearer tok" for v in cap["headers"].values())
    # Shares that also write to SWM use the longer store timeout, not the read one.
    assert cap["timeout"] == dkg_client._STORE_TIMEOUT


def test_share_rejects_oversized_literal_before_http(monkeypatch):
    def fail_urlopen(req, timeout=None):
        raise AssertionError("urlopen should not be called")

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", fail_urlopen)
    client = dkg_client.DkgClient(url="http://node", token="tok")
    rows = [{
        "subject": "urn:test:s",
        "predicate": "urn:test:p",
        "object": '"' + ("x" * 50001) + '"',
    }]
    with pytest.raises(dkg_client.DkgError, match="exceeds Blackbox cap"):
        client.share_knowledge_asset("cg", "notes", rows)


def test_register_context_graph_sends_policies(monkeypatch):
    cap = _capture(monkeypatch)
    client = dkg_client.DkgClient(url="http://node", token=None)
    client.register_context_graph("cg", access_policy=0, publish_policy=0)
    body = json.loads(cap["body"])
    assert body == {"id": "cg", "accessPolicy": 0, "publishPolicy": 0}
    assert cap["url"].endswith("/api/context-graph/register")


def test_redeliver_join_approval_payload(monkeypatch):
    cap = _capture(monkeypatch, body='{"ok":true,"delivered":true}')
    client = dkg_client.DkgClient(url="http://node", token="tok")
    out = client.redeliver_join_approval("umanitek/blackbox-threats-staging", "0xabc")
    assert out["delivered"] is True
    assert cap["method"] == "POST"
    assert cap["url"].endswith(
        "/api/context-graph/umanitek%2Fblackbox-threats-staging/redeliver-approval"
    )
    assert json.loads(cap["body"]) == {"agentAddress": "0xabc"}
    assert cap["timeout"] == dkg_client._STORE_TIMEOUT


def test_publish_payload(monkeypatch):
    cap = _capture(monkeypatch, body='{"ual":"did:dkg:1/2/3","txHash":"0xabc"}')
    client = dkg_client.DkgClient(url="http://node", token="t")
    out = client.publish("cg", "threat-x", epochs=3)
    assert out["ual"] == "did:dkg:1/2/3"
    assert cap["url"].endswith("/api/knowledge-assets/threat-x/vm/publish")
    body = json.loads(cap["body"])
    assert body["options"]["publishEpochs"] == 3


def test_query_normalizes_bindings(monkeypatch):
    body = json.dumps({"bindings": [{"identifier": '"dep:npm:x@1"'}]})
    _capture(monkeypatch, body=body)
    client = dkg_client.DkgClient(url="http://node", token="t")
    rows = client.query("SELECT * WHERE {?s ?p ?o}", "cg")
    assert rows == [{"identifier": '"dep:npm:x@1"'}]


def test_query_fails_open_on_http_error(monkeypatch):
    def raise_http(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 500, "err", {}, io.BytesIO(b"boom"))

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", raise_http)
    client = dkg_client.DkgClient(url="http://node", token="t")
    # query() swallows DkgError and returns [] (read paths fail open).
    assert client.query("SELECT * WHERE {?s ?p ?o}", "cg") == []


def test_write_path_raises_dkg_error_on_http_error(monkeypatch):
    def raise_http(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "forbidden", {}, io.BytesIO(b"nope"))

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", raise_http)
    client = dkg_client.DkgClient(url="http://node", token="t")
    with pytest.raises(dkg_client.DkgError):
        client.share_knowledge_asset("cg", "n", [])


def test_share_is_idempotent_on_already_finalized(monkeypatch):
    # Re-sharing a threat whose deterministic KA name already exists sealed must
    # be treated as success, not a 500 (verified live against a v10 node).
    body = b'{"error":"assertion ... is already finalized with a different merkleRoot"}'

    def raise_finalized(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 500, "err", {}, io.BytesIO(body))

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", raise_finalized)
    client = dkg_client.DkgClient(url="http://node", token="t")
    res = client.share_knowledge_asset("cg", "threat-abc", [])
    assert res.get("idempotent") is True


def test_onchain_calls_use_long_timeout(monkeypatch):
    # register/publish are on-chain and must not use the 3s read timeout.
    seen = {}

    def capture(req, timeout=None):
        seen["timeout"] = timeout
        return _FakeResponse('{"ok":true}')

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", capture)
    client = dkg_client.DkgClient(url="http://node", token="t")
    client.register_context_graph("cg", 0, 0)
    assert seen["timeout"] == dkg_client._ONCHAIN_TIMEOUT
    client.publish("cg", "n")
    assert seen["timeout"] == dkg_client._ONCHAIN_TIMEOUT


def test_extract_binding_shapes():
    assert dkg_client.extract_binding({"value": "foo"}) == "foo"
    assert dkg_client.extract_binding('"literal"') == "literal"
    assert dkg_client.extract_binding('"5"^^<http://www.w3.org/2001/XMLSchema#integer>') == "5"
    assert dkg_client.extract_binding("urn:guardian:threat:x") == "urn:guardian:threat:x"
    assert dkg_client.extract_binding(None) == ""


def test_normalize_bindings_nested_shape():
    result = {"results": {"bindings": [{"n": {"value": "3"}}]}}
    assert dkg_client.normalize_bindings(result) == [{"n": {"value": "3"}}]


def test_chain_info_parses_base_mainnet(monkeypatch):
    # /api/status reports the chain as a "base:8453" string on some builds.
    _capture(monkeypatch, body='{"chainId":"base:8453","networkName":"DKG V10 Base Mainnet"}')
    client = dkg_client.DkgClient(url="http://node", token="t")
    info = client.chain_info()
    assert info["chain_id"] == 8453
    assert info["is_mainnet"] is True
    assert info["is_testnet"] is False


def test_chain_info_flags_testnet(monkeypatch):
    _capture(monkeypatch, body='{"chainId":"base:84532","networkName":"Base Sepolia"}')
    client = dkg_client.DkgClient(url="http://node", token="t")
    info = client.chain_info()
    assert info["chain_id"] == 84532
    assert info["is_testnet"] is True
    assert info["is_mainnet"] is False


def test_chain_info_gnosis_is_mainnet_but_not_base(monkeypatch):
    # Nested chain object with an int id; Gnosis is a valid mainnet, not Base.
    _capture(monkeypatch, body='{"chain":{"chainId":100,"name":"gnosis"}}')
    client = dkg_client.DkgClient(url="http://node", token="t")
    info = client.chain_info()
    assert info["chain_id"] == 100
    assert info["is_mainnet"] is True
    assert info["chain_id"] != dkg_client.constants.DEFAULT_DKG_CHAIN_ID


def test_chain_info_unparseable_returns_none(monkeypatch):
    # An unrecognized status shape must not falsely claim mainnet/testnet.
    _capture(monkeypatch, body='{"foo":"bar"}')
    client = dkg_client.DkgClient(url="http://node", token="t")
    info = client.chain_info()
    assert info["chain_id"] is None
    assert info["is_mainnet"] is None
    assert info["is_testnet"] is None


def test_publish_idempotent_on_already_published(monkeypatch):
    # Re-publishing an already-minted KA (lost ledger / post-timeout confirm) is a
    # no-op success, never a paid retry or hard error.
    body = b'{"error":"knowledge asset is already published on chain"}'

    def raise_pub(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 409, "err", {}, io.BytesIO(body))

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", raise_pub)
    client = dkg_client.DkgClient(url="http://node", token="t")
    assert client.publish("cg", "threat-x").get("idempotent") is True


def test_publish_raises_on_context_graph_bind_failure(monkeypatch):
    # HTTP 207: minted (UAL valid) but CG binding failed — must surface as an
    # error, or the caller would ledger a threat that isn't queryable in the graph.
    _capture(monkeypatch, body='{"ual":"did:dkg:8453/0xabc/1","contextGraphError":"binding timed out"}')
    client = dkg_client.DkgClient(url="http://node", token="t")
    with pytest.raises(dkg_client.DkgError):
        client.publish("cg", "threat-x")
