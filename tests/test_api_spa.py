"""Tests for serving the built SPA — specifically that a deep link or a hard
refresh on a client-side route works.

A plain StaticFiles(html=True) mount resolves "/" but 404s
"/scans/<id>/overview", so the app only worked as long as you never reloaded
and never pasted a link. These pin the fallback behaviour down.
"""

from __future__ import annotations

from _fake_backend import FakeGraphBackend
from fastapi.testclient import TestClient

from pwngraph.api.app import create_app


def _static_dir(tmp_path):
    """A stand-in for `npm run build:pwngraph` output."""
    static = tmp_path / "static"
    # exist_ok: a couple of tests build a client more than once per tmp_path.
    (static / "assets").mkdir(parents=True, exist_ok=True)
    (static / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
    (static / "assets" / "index-abc.js").write_text("console.log(1)", encoding="utf-8")
    return static


def _client(tmp_path):
    return TestClient(create_app(FakeGraphBackend(), static_dir=_static_dir(tmp_path)))


def test_root_serves_the_app(tmp_path):
    resp = _client(tmp_path).get("/")
    assert resp.status_code == 200
    assert "id=root" in resp.text


def test_deep_link_to_a_client_route_serves_the_app(tmp_path):
    """The regression: React Router owns this path, so it must return
    index.html rather than 404 on a refresh or a pasted link."""
    resp = _client(tmp_path).get("/scans/abc123/overview")
    assert resp.status_code == 200
    assert "id=root" in resp.text


def test_nested_client_routes_also_fall_back(tmp_path):
    for path in ("/scans/abc123", "/scans/abc123/graph", "/scans/abc123/findings"):
        resp = _client(tmp_path).get(path)
        assert resp.status_code == 200, path
        assert "id=root" in resp.text


def test_real_asset_files_are_served_not_the_fallback(tmp_path):
    resp = _client(tmp_path).get("/assets/index-abc.js")
    assert resp.status_code == 200
    assert "console.log(1)" in resp.text


def test_missing_file_like_path_404s_instead_of_returning_html(tmp_path):
    """A mistyped asset URL quietly returning HTML with a 200 is far harder to
    debug than a 404."""
    assert _client(tmp_path).get("/assets/does-not-exist.js").status_code == 404
    assert _client(tmp_path).get("/favicon.ico").status_code == 404


def test_unknown_api_path_404s_as_api_not_as_the_app(tmp_path):
    resp = _client(tmp_path).get("/api/not-a-real-endpoint")
    assert resp.status_code == 404
    assert "id=root" not in resp.text


def test_api_routes_still_work_with_the_frontend_mounted(tmp_path):
    resp = _client(tmp_path).get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_path_traversal_cannot_escape_the_static_directory(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("do not serve me", encoding="utf-8")

    resp = _client(tmp_path).get("/../secret.txt")
    assert "do not serve me" not in resp.text


def test_api_only_mode_when_no_frontend_is_built(tmp_path):
    """`pwngraph serve` before `npm run build:pwngraph` — the API must still
    come up rather than failing to construct."""
    client = TestClient(create_app(FakeGraphBackend(), static_dir=tmp_path / "nope"))
    assert client.get("/api/health").status_code == 200
    assert client.get("/").status_code == 404


def test_token_in_page_url_lets_the_viewer_call_the_api(tmp_path):
    """With --token, the frontend sends no header — opening /?token= once must
    set a cookie its same-origin API calls then authenticate with."""
    app = create_app(FakeGraphBackend(), static_dir=_static_dir(tmp_path), api_token="s3cret")
    client = TestClient(app)
    assert client.get("/api/scans").status_code == 401
    assert client.get("/?token=wrong").status_code == 200
    assert client.get("/api/scans").status_code == 401
    assert client.get("/?token=s3cret").status_code == 200
    assert client.get("/api/scans").status_code == 200
