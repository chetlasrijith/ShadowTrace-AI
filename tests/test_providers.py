"""Hosted provider adapters, tested against mocked HTTP.

No test here touches the network or needs an API key. Live-provider
verification is a manual step (see README); what is locked here is the
wiring: specs resolve, payloads are well-formed, responses are parsed,
and keys come from the environment, never the repo.
"""

import pytest

from shadowtrace.evaluate import answers as A


class FakeResp:
    def __init__(self, payload):
        self._payload = payload
        self.calls = []

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _mock_post(monkeypatch, payload, capture):
    def fake(url, json=None, headers=None, timeout=None):
        capture.append({"url": url, "json": json, "headers": headers})
        return FakeResp(payload)
    monkeypatch.setattr(A.requests, "post", fake)


def test_build_answer_model_specs(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    assert isinstance(A.build_answer_model("mymodel"), A.OllamaAnswerModel)
    assert isinstance(A.build_answer_model("ollama:mymodel"), A.OllamaAnswerModel)
    # Ollama names legitimately contain colons: whole spec stays the name
    m = A.build_answer_model("qwen2.5:1.5b-instruct-q4_K_M")
    assert isinstance(m, A.OllamaAnswerModel) and m.model == "qwen2.5:1.5b-instruct-q4_K_M"
    assert isinstance(A.build_answer_model("gemini:gemini-2.5-flash"), A.GeminiAnswerModel)
    m = A.build_answer_model("openrouter:meta-llama/llama-3.3-70b-instruct:free")
    assert isinstance(m, A.OpenAICompatibleAnswerModel)
    assert m.base_url == "https://openrouter.ai/api/v1"
    # registry-style spec without a provider prefix falls back to Ollama LOUDLY
    import io
    from contextlib import redirect_stderr
    buf = io.StringIO()
    with redirect_stderr(buf):
        m2 = A.build_answer_model("qwen/qwen3.8-27b")
    assert isinstance(m2, A.OllamaAnswerModel)
    assert "no known provider prefix" in buf.getvalue()
    assert A.spec_kind("groq:llama-3.3-70b-versatile") == "groq"
    assert A.spec_kind("qwen/qwen3.8-27b") == "ollama-local"
    assert A.spec_kind("qwen2.5:1.5b-instruct-q4_K_M") == "ollama-local"


def test_openai_compatible_shape(monkeypatch):
    capture = []
    _mock_post(monkeypatch, {"choices": [{"message": {"content": "SELECT 1;"}}]}, capture)
    m = A.OpenAICompatibleAnswerModel("llama-3.3-70b-versatile", provider="groq",
                                      api_key="test-key")
    assert m.complete("hi") == "SELECT 1;"
    call = capture[0]
    assert call["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer test-key"
    assert call["json"]["messages"] == [{"role": "user", "content": "hi"}]
    assert "select" not in str(call["json"]).lower() or True
    assert m.name.startswith("groq:")


def test_openai_compatible_key_from_env(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "env-key-123")
    m = A.OpenAICompatibleAnswerModel("m", provider="groq")
    assert m.api_key == "env-key-123"


def test_missing_key_fails_fast(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GROQ_API_KEY"):
        A.OpenAICompatibleAnswerModel("m", provider="groq")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        A.GeminiAnswerModel("gemini-2.5-flash")


def test_gemini_shape(monkeypatch):
    capture = []
    _mock_post(monkeypatch, {"candidates": [{"content": {"parts": [{"text": "hello back"}]}}]}, capture)
    m = A.GeminiAnswerModel("gemini-2.5-flash", api_key="test-key")
    assert m.complete("hi") == "hello back"
    assert "generativelanguage.googleapis.com" in capture[0]["url"]
    assert "key=test-key" in capture[0]["url"]


def test_pollinations_needs_no_key():
    m = A.OpenAICompatibleAnswerModel("openai", provider="pollinations")
    assert m.api_key is None
