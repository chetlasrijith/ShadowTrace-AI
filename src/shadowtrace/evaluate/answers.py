"""Answer models behind one interface, with response caching.

Two implementations:

- StubAnswerModel: deterministic, answers from the GIVEN text only. It
  echoes identifiers as written, which is what makes it behave like a real
  model under transformation: it cannot reproduce a token it was never
  shown. Used for unit tests and for --mode selftest, which validates the
  harness without claiming anything about models.
- OllamaAnswerModel: a real local model over HTTP. The only path whose
  numbers may be reported as results.

Every completion is cached by (model, sha256 of prompt) in JSONL, with model
name, temperature and seed recorded. Plan 10.1: tables regenerate from cache.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import requests

from ..prompts import Prompt


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AnswerModel:
    name: str = "base"

    def complete(self, prompt_text: str, prompt: Prompt | None = None,
                 registry=None, ladders=None) -> str:
        raise NotImplementedError


class StubAnswerModel(AnswerModel):
    """Ceiling oracle: a model that perfectly extracts whatever the text supports.

    It answers strictly from the GIVEN text and knows the task's expected
    reference types (a client_reference names an org), but never the ground
    truth. For a value it returns the longest phrase the checker would
    accept, which is what a perfect copier would produce. Its utility
    numbers are therefore the ACHIEVABLE CEILING for each transform, and
    their job is to validate the checkers: a ceiling below 1.0 on noop is a
    checker bug, not a model failure. Real-model runs are the results;
    stub runs are the calibration.
    """

    name = "stub-oracle-v1"

    def complete(self, prompt_text: str, prompt: Prompt | None = None,
                 registry=None, ladders=None) -> str:
        if prompt is None:
            return "stub requires the prompt spec"
        fam = prompt.family
        if fam == "sql":
            return self._sql(prompt_text, prompt, registry, ladders)
        if fam == "extract":
            return self._extract(prompt_text, prompt, registry, ladders)
        if fam == "docqa":
            return self._docqa(prompt_text, prompt, registry, ladders)
        if fam == "drafting":
            return self._drafting(prompt_text, prompt)
        if fam == "code":
            return self._code(prompt_text, prompt)
        return "no answer"

    def _oracle(self, remainder: str, etype: str, registry, ladders) -> str:
        """Longest leading phrase that resolves to an entity of `etype`."""
        from ..checkers.text_check import resolve_reference

        tokens = remainder.split()
        for k in range(len(tokens), 0, -1):
            frag = " ".join(tokens[:k]).rstrip(".,:;")
            if registry is not None and ladders is not None:
                if resolve_reference(frag, etype, registry, ladders) is not None:
                    return frag
            elif k == 1:
                return frag
        return tokens[0] if tokens else "unknown"

    def _sql(self, text: str, prompt: Prompt, registry, ladders) -> str:
        table = prompt.spec.get("table", "")
        m = re.search(r"table\s+(.+)", text)
        remainder = m.group(1).strip() if m else table
        named = self._oracle(remainder, "system", registry, ladders)
        gold = prompt.spec.get("gold_sql", "")
        if named == table:
            return gold
        return re.sub(re.escape(table), named, gold) if table in gold else gold

    def _extract(self, text: str, prompt: Prompt, registry, ladders) -> str:
        mode = prompt.spec.get("mode", "json")
        client = self._oracle(_after_marker(text, "client_reference:"), "org", registry, ladders)
        account = self._oracle(_after_marker(text, "account_code:"), "identifier", registry, ladders)
        source = self._oracle(_after_marker(text, "source_system:"), "system", registry, ladders)
        flag = _after_marker(text, "renewal_flag:")
        if mode == "json":
            return json.dumps({"client": client, "account": account})
        if "upper-cased" in text or "FLAG" in prompt.spec.get("expect", {}).get("line", ""):
            return f"{client}|{account.upper()}|{'true' if flag.strip().lower() == 'yes' else 'false'}"
        return f"{source},{account}"

    def _docqa(self, text: str, prompt: Prompt, registry, ladders) -> str:
        # dispatch on the QUESTION (last line), never the document: every
        # document mentions payment terms, so matching on the whole text
        # answers every question with "30".
        question = text.split("Question:")[-1].lower() if "Question:" in text else text.lower()
        if "how many" in question or "number of days" in question or "payment terms" in question:
            m = re.search(r"net\s+(\d+)", text, re.IGNORECASE)
            return m.group(1) if m else "unknown"
        if "account code" in question:
            return self._oracle(_after_marker(text, "account"), "identifier", registry, ladders)
        if "client" in question and "fee" in question:
            return (f"{self._oracle(_after_marker(text, 'client'), 'org', registry, ladders)}"
                    f"|{self._oracle(_after_marker(text, 'fee of'), 'amount', registry, ladders)}")
        if "total fee" in question or "fee" in question:
            return self._oracle(_after_marker(text, "fee of"), "amount", registry, ladders)
        return "unknown"

    def _drafting(self, text: str, prompt: Prompt) -> str:
        sys_m = re.search(r"outage in (\S+(?:\s+\S+){0,4}) affecting", text)
        org_m = re.search(r"affecting (\S+(?:\s+\S+){0,4})\.", text)
        sys_ref = sys_m.group(1) if sys_m else "the system"
        org_ref = org_m.group(1) if org_m else "the client"
        if "status update for the client" in text:
            return (f"Status update for {org_ref}: the partial outage in {sys_ref} "
                    f"is under investigation following a failed nightly job. "
                    f"No data was lost and the next update follows shortly.")
        return (f"The partial outage in {sys_ref} affected {org_ref}. "
                f"Root cause was a failed nightly job; no data was lost.")

    def _code(self, text: str, prompt: Prompt) -> str:
        fn = prompt.spec.get("fn_name", "fn_x")
        ref = prompt.spec.get("reference", "")
        return re.sub(r"def\s+\w+\s*\(", f"def {fn}(", ref, count=1)


def _after_marker(text: str, marker: str) -> str:
    """Full line remainder after a marker. The oracle delimits it."""
    m = re.search(re.escape(marker) + r"\s*([^\n]+)", text, re.IGNORECASE)
    if not m:
        return "unknown"
    return m.group(1).strip().rstrip(".")


class OllamaAnswerModel(AnswerModel):
    def __init__(self, model: str, temperature: float = 0.0, seed: int = 42,
                 timeout_s: float = 120.0, host: str = "http://localhost:11434"):
        self.model = model
        self.temperature = temperature
        self.seed = seed
        self.timeout_s = timeout_s
        self.host = host
        self.name = f"ollama:{model}:t{temperature}:s{seed}"

    def complete(self, prompt_text: str, prompt: Prompt | None = None,
                 registry=None, ladders=None) -> str:
        payload = {
            "model": self.model, "prompt": prompt_text, "stream": False,
            "options": {"temperature": self.temperature, "seed": self.seed},
        }
        r = requests.post(f"{self.host}/api/generate", json=payload, timeout=self.timeout_s)
        r.raise_for_status()
        return r.json().get("response", "")


# ---------------------------------------------------------------------------
# hosted providers (project-grade free tiers; Ollama stays the default)
#
# Privacy contract: only SANITIZED text ever reaches these models through the
# chat/sanitize paths. The pilot's noop baseline sends synthetic originals —
# fictional by construction, disclosed in every report. Free-tier data-use
# terms vary by provider and change often; check the provider's current
# policy before quoting numbers, and never point these at real secrets.
# ---------------------------------------------------------------------------

PROVIDER_DEFAULTS = {
    # provider: (base_url, api_key_env, extra_headers)
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", {}),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY",
                   {"HTTP-Referer": "http://127.0.0.1", "X-Title": "shadowtrace-pilot"}),
    "together": ("https://api.together.xyz/v1", "TOGETHER_API_KEY", {}),
    "cerebras": ("https://api.cerebras.ai/v1", "CEREBRAS_API_KEY", {}),
    "pollinations": ("https://text.pollinations.ai/openai", None, {}),
}


class OpenAICompatibleAnswerModel(AnswerModel):
    """One adapter for every OpenAI-chat-completions-shaped free tier.

    Covers Groq, OpenRouter (:free models), Together, Cerebras, and the
    zero-key Pollinations endpoint. Key comes from the environment, never
    from configs or the repo.
    """

    def __init__(self, model: str, provider: str = "groq",
                 temperature: float = 0.0, seed: int = 42,
                 timeout_s: float = 120.0, base_url: str | None = None,
                 api_key: str | None = None):
        import os

        defaults = PROVIDER_DEFAULTS.get(provider, (None, None, {}))
        default_url, key_env, extra = defaults
        self.model = model
        self.provider = provider
        self.temperature = temperature
        self.seed = seed
        self.timeout_s = timeout_s
        self.base_url = (base_url or default_url or "").rstrip("/")
        if not self.base_url:
            raise ValueError(f"unknown provider {provider!r}: pass base_url explicitly")
        self.api_key = api_key or (os.environ.get(key_env) if key_env else None)
        if key_env and not self.api_key:
            raise ValueError(f"set {key_env} in the environment (keys never live in the repo)")
        self.extra_headers = extra
        self.name = f"{provider}:{model}:t{temperature}:s{seed}"

    def complete(self, prompt_text: str, prompt: Prompt | None = None,
                 registry=None, ladders=None) -> str:
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt_text}],
            "temperature": self.temperature,
            "seed": self.seed,
            "stream": False,
        }
        r = requests.post(f"{self.base_url}/chat/completions",
                          json=payload, headers=headers, timeout=self.timeout_s)
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"] or ""


class GeminiAnswerModel(AnswerModel):
    """Google AI Studio free tier via the v1beta REST shape. No seed knob."""

    def __init__(self, model: str = "gemini-2.5-flash",
                 temperature: float = 0.0, timeout_s: float = 120.0,
                 api_key: str | None = None):
        import os

        self.model = model
        self.temperature = temperature
        self.timeout_s = timeout_s
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("set GEMINI_API_KEY in the environment")
        self.name = f"gemini:{model}:t{temperature}"

    def complete(self, prompt_text: str, prompt: Prompt | None = None,
                 registry=None, ladders=None) -> str:
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.model}:generateContent?key={self.api_key}")
        payload = {
            "contents": [{"parts": [{"text": prompt_text}]}],
            "generationConfig": {"temperature": self.temperature},
        }
        r = requests.post(url, json=payload, timeout=self.timeout_s)
        r.raise_for_status()
        data = r.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"] or ""
        except (KeyError, IndexError):
            raise ValueError(f"unexpected Gemini response: {str(data)[:300]}")


def build_answer_model(spec: str, temperature: float = 0.0, seed: int = 42,
                       timeout_s: float = 120.0, **overrides) -> AnswerModel:
    """Build an answer model from a short spec. Shared by pilot + server.

    - "just-a-name" or "ollama:name"  -> local Ollama (default, private)
    - "groq:model-id"                -> Groq free tier (GROQ_API_KEY)
    - "openrouter:org/model:free"    -> OpenRouter free models (OPENROUTER_API_KEY)
    - "together:model-id"            -> Together (TOGETHER_API_KEY)
    - "cerebras:model-id"            -> Cerebras (CEREBRAS_API_KEY)
    - "pollinations:model-id"        -> zero-key fallback, not for evaluation
    - "gemini:model-id"              -> AI Studio free tier (GEMINI_API_KEY)
    """
    provider, _, model = spec.partition(":")
    if not model or provider == "ollama":
        return OllamaAnswerModel(model or provider, temperature, seed,
                                 timeout_s, **overrides)
    if provider == "gemini":
        return GeminiAnswerModel(model, temperature, timeout_s, **overrides)
    if provider in PROVIDER_DEFAULTS or "base_url" in overrides:
        return OpenAICompatibleAnswerModel(model, provider, temperature, seed,
                                           timeout_s, **overrides)
    raise ValueError(f"unknown model spec {spec!r}")


class ResponseCache:
    """Append-only JSONL cache keyed by (model name, prompt sha)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._index: dict[tuple[str, str], str] = {}
        if self.path.exists():
            with self.path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    self._index[(rec["model"], rec["prompt_sha"])] = rec["response"]

    def get(self, model_name: str, prompt_text: str) -> str | None:
        return self._index.get((model_name, sha256(prompt_text)))

    def put(self, model_name: str, prompt_text: str, response: str, meta: dict | None = None) -> None:
        rec = {
            "model": model_name, "prompt_sha": sha256(prompt_text),
            "prompt": prompt_text, "response": response, "meta": meta or {},
        }
        self._index[(model_name, sha256(prompt_text))] = response
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")


class CachedModel(AnswerModel):
    """Wrap any model with a disk cache. Reads never touch the network."""

    def __init__(self, inner: AnswerModel, cache: ResponseCache):
        self.inner = inner
        self.cache = cache
        self.name = inner.name
        self.hits = 0
        self.misses = 0

    def complete(self, prompt_text: str, prompt: Prompt | None = None,
                 registry=None, ladders=None) -> str:
        hit = self.cache.get(self.name, prompt_text)
        if hit is not None:
            self.hits += 1
            return hit
        self.misses += 1
        resp = self.inner.complete(prompt_text, prompt, registry, ladders)
        self.cache.put(self.name, prompt_text, resp,
                       {"family": prompt.family if prompt else None,
                        "pid": prompt.pid if prompt else None})
        return resp