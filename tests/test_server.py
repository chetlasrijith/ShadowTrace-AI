"""Server endpoint tests: /api/sanitize composes the tested pipeline.

No answer model is touched here; sanitize must never call Ollama, so these
run offline in milliseconds against the local app object.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
ROOT_STATIC = ROOT / "server" / "static"

from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402

client = TestClient(app)


def test_health_reports_ladders_v2():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] and body["entities"] > 100
    assert body["ladders_version"] == 2


def test_sanitize_chat_text_generalize():
    r = client.post("/api/sanitize", json={
        "text": "Client Id is 123893 and client pass is shara@123",
        "method": "generalize",
    })
    assert r.status_code == 200
    d = r.json()
    assert d["method"] == "generalize" and not d["held"]
    assert {s["surface"] for s in d["spans"]} == {"123893", "shara@123"}
    assert "123893" not in d["sanitized"] and "shara@123" not in d["sanitized"]
    assert "[PASSWORD]" in d["sanitized"]
    assert d["leakage"]["span"]["rate"] == 0.0
    assert d["attack"]["total"] == 2 and d["attack"]["rate"] == 0.0
    assert "answer" not in d  # sanitize never answers


def test_sanitize_redact_placeholders():
    r = client.post("/api/sanitize", json={
        "text": "Client Id is 123893 and client pass is shara@123",
        "method": "redact",
    })
    d = r.json()
    assert d["sanitized"] == "Client Id is [EMPLOYEE_ID] and client pass is [PASSWORD]"


def test_sanitize_clean_text_passes_through():
    r = client.post("/api/sanitize", json={
        "text": "Explain how photosynthesis works.",
        "method": "generalize",
    })
    d = r.json()
    assert d["spans"] == [] and d["sanitized"] == d["normalized"]
    assert d["attack"] is None


def test_sanitize_rung_shift_reaches_placeholder():
    r = client.post("/api/sanitize", json={
        "text": "Client Id is 123893",
        "method": "generalize",
        "rung_shift": 2,
    })
    assert "[EMPLOYEE_ID]" in r.json()["sanitized"]


def test_ladders_endpoint_lists_adhoc_types():
    r = client.get("/api/ladders")
    assert set(r.json()["ladders"]) >= {
        "email", "phone", "password", "employee_id", "api_key", "card",
    }


def test_cors_helper_defaults_to_same_origin(monkeypatch):
    from app import cors_origins_from_env

    monkeypatch.delenv("SHADOWTRACE_CORS_ORIGINS", raising=False)
    assert cors_origins_from_env() == []
    monkeypatch.setenv(
        "SHADOWTRACE_CORS_ORIGINS",
        "https://shadowtrace.vercel.app, https://www.example.com/ ",
    )
    assert cors_origins_from_env() == [
        "https://shadowtrace.vercel.app", "https://www.example.com",
    ]


def test_frontend_routes_all_api_calls_through_base():
    src = (ROOT_STATIC / "app.js").read_text(encoding="utf-8")
    assert "window.SHADOWTRACE_API_BASE" in src
    assert 'fetch("/api/' not in src  # no bare same-origin calls left
    cfg = (ROOT_STATIC / "api-config.js").read_text(encoding="utf-8")
    assert 'window.SHADOWTRACE_API_BASE = ""' in cfg
    html = (ROOT_STATIC / "index.html").read_text(encoding="utf-8")
    assert "api-config.js" in html
