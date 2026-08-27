"""Target provider abstraction.

A `Provider` represents the **system under test** — the thing we send attack
prompts to and later grade. This module is deliberately scoped to the *target*
only; the logic for *generating* adversarial prompts lives in the `plugins`
layer, since authoring attacks is a plugin's responsibility.

The design is a template method: the base `Provider` owns everything that is
backend-independent — turning a prompt into a message list, attaching the
system prompt, trimming the output — while a concrete backend implements the
single `_complete()` hook that actually talks to its API.

Adding a real target later is a small, self-contained subclass; nothing else in
the pipeline needs to change. For example:

    class AnthropicTarget(Provider):
        def __init__(self, model="claude-opus-4-8", **kw):
            super().__init__(model, **kw)
            import anthropic
            self._client = anthropic.Anthropic()

        def _complete(self, messages):
            system = next((m["content"] for m in messages if m["role"] == "system"), None)
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system,
                messages=[m for m in messages if m["role"] != "system"],
                **self.params,
            )
            return "".join(b.text for b in resp.content if b.type == "text")
"""

from __future__ import annotations

import importlib.util
from abc import ABC, abstractmethod
from collections import deque
from pathlib import Path
from typing import Any, Callable, Iterable

# Provider-neutral chat message. Backends map these onto their own API shape
# (e.g. a "system" message becomes Anthropic's top-level `system` parameter).
Message = dict[str, str]  # {"role": "system"|"user"|"assistant", "content": str}


class Provider(ABC):
    """Generalized target model. Subclass and implement `_complete()`."""

    #: Human-readable identifier, surfaced in reports/metadata.
    name: str = "provider"

    def __init__(
        self,
        model: str | None = None,
        *,
        system: str | None = None,
        max_tokens: int = 4096,
        params: dict[str, Any] | None = None,
    ) -> None:
        self.model = model
        self.system = system
        self.max_tokens = max_tokens
        # Backend-specific knobs (effort, temperature, thinking, ...) kept open
        # so subclasses can expand without changing the base surface.
        self.params: dict[str, Any] = dict(params or {})
        if model and self.name == "provider":
            self.name = model

    # ---- public API -------------------------------------------------------

    def generate(self, prompt: "str | list[Message]", *, system: str | None = None) -> str:
        """Send a prompt (string or message list) to the target and return its
        text response. A multi-turn message list supports multi-step strategies."""
        import time as _time
        messages = self._coerce_messages(prompt, system if system is not None else self.system)
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                return self._postprocess(self._complete(messages))
            except Exception as exc:
                last_exc = exc
                if attempt < 2:
                    _time.sleep(2 ** attempt)  # 1s, 2s
        raise last_exc

    # ---- backend hook (the only thing subclasses must implement) ----------

    @abstractmethod
    def _complete(self, messages: list[Message]) -> str:
        """Call the underlying model and return its raw text output."""
        raise NotImplementedError

    # ---- shared helpers (override only if a backend needs to) -------------

    @staticmethod
    def _coerce_messages(prompt: "str | list[Message]", system: str | None) -> list[Message]:
        messages: list[Message] = []
        if system:
            messages.append({"role": "system", "content": system})
        if isinstance(prompt, str):
            messages.append({"role": "user", "content": prompt})
        else:
            messages.extend(prompt)
        return messages

    def _postprocess(self, text: str) -> str:
        return text.strip()


class ScriptedProvider(Provider):
    """A target that replays canned responses in order. Lets the attack -> grade
    flow run offline in tests without an API key or token spend."""

    name = "scripted"

    def __init__(self, responses: Iterable[str]) -> None:
        super().__init__(model=None)
        self._queue: deque[str] = deque(responses)

    def _complete(self, messages: list[Message]) -> str:
        if not self._queue:
            raise RuntimeError("ScriptedProvider ran out of scripted responses")
        return self._queue.popleft()


class RestProvider(Provider):
    """Generic REST target.

    Two modes selected by whether ``req_template`` is provided:

    **Template mode** (``type: rest``) — any API shape:
        Supply a ``req_template`` dict whose values may contain ``$INPUT``
        (replaced with the prompt) and ``$KEY`` (replaced with ``api_key``).
        Supply ``response_field`` as dot-notation to extract the reply
        (e.g. ``"output.text"`` or ``"choices.0.message.content"``).

    **OpenAI mode** (``type: openai``) — no template needed:
        Sends the standard ``POST /v1/chat/completions`` payload and reads
        ``choices[0].message.content``.
    """

    def __init__(
        self,
        base_url: str,
        model: str = "",
        *,
        api_key: str | None = None,
        req_template: "dict | None" = None,
        response_field: str | None = None,
        method: str = "post",
        extra_headers: "dict | None" = None,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.0,
        timeout: int = 60,
        **params: Any,
    ) -> None:
        super().__init__(model=model or base_url, system=system, max_tokens=max_tokens)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.req_template = req_template
        self.response_field = response_field
        self.method = method.lower()
        self.extra_headers: dict[str, str] = dict(extra_headers or {})
        self.temperature = temperature
        self.timeout = timeout
        self.params.update(params)
        self.name = model or base_url
        self._session = None  # lazily built; reused so TLS/TCP setup is paid once

    # ---- helpers -------------------------------------------------------------

    def _get_session(self):
        """A pooled `requests.Session`, built once per provider.

        Without this every call opened a fresh connection — a full TCP and TLS
        handshake per attack, which against a remote HTTPS endpoint costs more
        than the request itself. The pool is sized for the largest concurrency
        the runner is likely to drive through one provider instance.
        """
        if self._session is None:
            import requests
            from requests.adapters import HTTPAdapter

            session = requests.Session()
            # max_retries=0: Provider.generate() already retries with backoff,
            # and stacking urllib3's retries on top would multiply the delay.
            adapter = HTTPAdapter(pool_connections=32, pool_maxsize=64, max_retries=0)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._session = session
        return self._session

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        for k, v in self.extra_headers.items():
            headers[k] = v.replace("$KEY", self.api_key or "")
        if self.api_key and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    @staticmethod
    def _fill(obj: Any, prompt: str) -> Any:
        """Recursively replace ``$INPUT`` in a template dict/string."""
        if isinstance(obj, str):
            return obj.replace("$INPUT", prompt)
        if isinstance(obj, dict):
            return {k: RestProvider._fill(v, prompt) for k, v in obj.items()}
        if isinstance(obj, list):
            return [RestProvider._fill(v, prompt) for v in obj]
        return obj

    @staticmethod
    def _extract(data: Any, field: str) -> str:
        """Pull a value from a JSON response using dot-notation.

        ``"output.text"``              → ``data["output"]["text"]``
        ``"choices.0.message.content"``→ ``data["choices"][0]["message"]["content"]``

        Raises ValueError with helpful diagnostics if field is not found.
        """
        import json as _json
        parts = field.split(".")
        current = data
        path_taken = []

        try:
            for part in parts:
                path_taken.append(part)
                if isinstance(current, list):
                    idx = int(part)
                    current = current[idx]
                else:
                    current = current[part]
            # null content (reasoning-only / filtered / refusal) → "" not "None"
            return "" if current is None else str(current)
        except (KeyError, IndexError, ValueError, TypeError) as e:
            # Show what we found vs what was expected
            raise ValueError(
                f"Cannot extract field '{field}' from response.\n"
                f"Failed at: {'.'.join(path_taken)}\n"
                f"Available keys: {list(data.keys()) if isinstance(data, dict) else 'not a dict'}\n"
                f"Full response:\n{_json.dumps(data, indent=2)[:1000]}"
            )

    # ---- core ----------------------------------------------------------------

    def _complete(self, messages: list[Message]) -> str:
        import requests  # lazy — not a hard dep for offline use
        import json as _json

        headers = self._build_headers()

        if self.req_template is not None:
            # Template mode — extract the last user message and fill $INPUT
            prompt = next(
                (m["content"] for m in reversed(messages) if m["role"] == "user"), ""
            )
            body = self._fill(self.req_template, prompt)
            url = self.base_url  # full endpoint URL supplied by the user
        else:
            # OpenAI-compatible mode
            body = {
                "model": self.model,
                "messages": messages,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                **{k: v for k, v in self.params.items()
                   if k not in ("model", "messages")},
            }
            # Accept any common form of the base URL rather than blindly
            # appending — users paste the bare host, the /v1 root, or the full
            # endpoint. Appending unconditionally doubled the path
            # (…/v1/chat/completions/v1/chat/completions → 404).
            b = self.base_url
            if b.endswith("/chat/completions"):
                url = b
            elif b.endswith("/v1"):
                url = f"{b}/chat/completions"
            else:
                url = f"{b}/v1/chat/completions"

        http_fn = getattr(self._get_session(), self.method)
        resp = http_fn(url, json=body, headers=headers, timeout=self.timeout)

        # Handle HTTP errors with helpful messages
        if not resp.ok:
            error_hints = {
                401: "Invalid or missing API key. Check 'api_key' in your config.",
                403: "Permission denied. Check your API key has the right scopes.",
                404: "Endpoint not found. Check 'name' (base URL) in your config.",
                429: "Rate limited. Wait before retrying.",
                500: "Server error. Check if the API is running.",
                502: "Bad gateway. The API server may be down.",
                503: "Service unavailable. Try again later.",
            }
            hint = error_hints.get(resp.status_code, "Check the API endpoint and credentials.")
            raise ValueError(
                f"HTTP {resp.status_code} {resp.reason}\n"
                f"URL: {url}\n"
                f"Response: {resp.text[:500]}\n"
                f"Hint: {hint}"
            )

        # Parse and validate response
        try:
            data = resp.json()
        except _json.JSONDecodeError as e:
            raise ValueError(
                f"API returned invalid JSON. Status {resp.status_code}. "
                f"Response: {resp.text[:500]}\nError: {e}"
            )

        # Extract response text (auto-detect if response_field not specified)
        if self.response_field:
            # User specified field path
            try:
                return self._extract(data, self.response_field)
            except (KeyError, IndexError, ValueError, TypeError) as e:
                raise ValueError(f"Cannot extract field '{self.response_field}': {e}")

        # Auto-detect: try common response patterns
        common_paths = [
            "response",                      # custom: {"response": "text"}
            "output",                        # custom: {"output": "text"}
            "text",                          # custom: {"text": "text"}
            "result",                        # custom: {"result": "text"}
            "message",                       # custom: {"message": "text"}
            "content",                       # custom: {"content": "text"}
            "choices.0.message.content",     # OpenAI format
            "choices.0.text",                # Some models
            "data.0.message.content",        # Alternative format
        ]

        for path in common_paths:
            try:
                return self._extract(data, path)
            except (KeyError, IndexError, ValueError, TypeError):
                continue

        # Last resort: return first string value in response
        def find_first_string(obj):
            if isinstance(obj, str):
                return obj
            if isinstance(obj, dict):
                for v in obj.values():
                    result = find_first_string(v)
                    if result:
                        return result
            elif isinstance(obj, list) and obj:
                return find_first_string(obj[0])
            return None

        text = find_first_string(data)
        if text:
            return text

        # If still nothing, return full response as string
        return _json.dumps(data)

    @classmethod
    def from_config_file(cls, path: "str | Path", *, api_key: str | None = None) -> "RestProvider":
        """Load a RestProvider from a YAML/JSON generator config file.

        Config file format::

            url: http://my-api:8080/generate
            method: post            # optional, default: post
            model: my-model         # optional
            api_key: sk-...         # optional — override with --target-api-key
            headers:
              Authorization: "Bearer $KEY"
            request:
              message: "$INPUT"
              max_tokens: 512
            response_field: output.text
        """
        import json as _json

        p = Path(path)
        text = p.read_text(encoding="utf-8")
        if p.suffix in (".yaml", ".yml"):
            import yaml as _yaml
            spec: dict[str, Any] = _yaml.safe_load(text)
        else:
            spec = _json.loads(text)

        return cls(
            base_url=spec["url"],
            model=spec.get("model", ""),
            api_key=api_key or spec.get("api_key"),
            req_template=spec.get("request"),
            response_field=spec.get("response_field"),
            method=spec.get("method", "post"),
            extra_headers=spec.get("headers", {}),
        )


class AnthropicProvider(Provider):
    """Target backed by the Anthropic API (Claude models).

    Sends prompts to Claude via the Anthropic SDK with full message/system
    prompt support. Handles streaming and non-streaming responses.
    """

    name = "anthropic"

    def __init__(
        self,
        model: str = "claude-opus-4-8",
        *,
        api_key: str | None = None,
        max_tokens: int = 4096,
        **params: Any,
    ) -> None:
        super().__init__(model=model, max_tokens=max_tokens, params=params)
        import os
        import anthropic

        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )

    def _complete(self, messages: list[Message]) -> str:
        # Extract system message if present
        system = next((m["content"] for m in messages if m["role"] == "system"), None)
        # Filter out system messages from the messages list
        non_system_messages = [m for m in messages if m["role"] != "system"]

        response = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=non_system_messages,
            **self.params,
        )
        return "".join(b.text for b in response.content if b.type == "text")


class MistralProvider(Provider):
    """Target backed by the Mistral API.

    Sends prompts to Mistral models via the Mistral SDK with full message/system
    prompt support.
    """

    name = "mistral"

    def __init__(
        self,
        model: str = "mistral-large-latest",
        *,
        api_key: str | None = None,
        max_tokens: int = 4096,
        **params: Any,
    ) -> None:
        super().__init__(model=model, max_tokens=max_tokens, params=params)
        import os
        from mistralai.client import Mistral

        self._client = Mistral(api_key=api_key or os.environ.get("MISTRAL_API_KEY"))

    def _complete(self, messages: list[Message]) -> str:
        response = self._client.chat.complete(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
            **self.params,
        )
        return response.choices[0].message.content or ""


class CallableProvider(Provider):
    """Target backed by a Python callable ``f(prompt: str) -> str``.

    Equivalent to Garak's ``-G module_file`` / promptfoo's ``python:`` provider.
    Load a custom Python file and call its ``invoke`` function::

        # my_target.py
        def invoke(prompt: str) -> str:
            return my_model.generate(prompt)

    Pass the path via ``--target-module my_target.py``.
    """

    def __init__(self, fn: Callable[[str], str], *, name: str = "callable") -> None:
        super().__init__(model=None)
        self._fn = fn
        self.name = name

    @classmethod
    def from_module_spec(cls, spec: str) -> "CallableProvider":
        """Load a callable using Garak-style ``module_name#function_name`` syntax.

        Examples::

            test_func#check_api_key       # importable module on sys.path
            mypackage.target#invoke       # dotted module path
            test_func.py#check_api_key    # .py path resolved relative to cwd

        If ``#function_name`` is omitted, looks for ``invoke`` by default.
        """
        import sys

        fn_name: str | None = None
        if "#" in spec:
            module_spec, fn_name = spec.split("#", 1)
        else:
            module_spec = spec

        # Resolve .py paths and ensure the containing directory is importable.
        if module_spec.endswith(".py"):
            p = Path(module_spec).resolve()
            module_spec = p.stem
            search_dir = str(p.parent)
        else:
            search_dir = str(Path.cwd())

        if search_dir not in sys.path:
            sys.path.insert(0, search_dir)

        mod = importlib.import_module(module_spec)

        if fn_name:
            if not hasattr(mod, fn_name):
                raise AttributeError(
                    f"module '{module_spec}' has no function '{fn_name}'"
                )
            fn = getattr(mod, fn_name)
        elif hasattr(mod, "invoke"):
            fn = mod.invoke
        else:
            raise AttributeError(
                f"module '{module_spec}' must define 'invoke(prompt: str) -> str'  "
                f"or use  {module_spec}#function_name  to pick a specific function"
            )
        return cls(fn, name=f"{module_spec}#{fn.__name__}")

    def _complete(self, messages: list[Message]) -> str:
        prompt = next(
            (m["content"] for m in reversed(messages) if m["role"] == "user"), ""
        )
        return self._fn(prompt)
