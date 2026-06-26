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
        messages = self._coerce_messages(prompt, system if system is not None else self.system)
        return self._postprocess(self._complete(messages))

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
    """Target that calls any OpenAI-compatible REST endpoint.

    Equivalent to Garak's ``--model_type rest`` / promptfoo's ``http:`` provider.
    Point it at any server that speaks ``POST /v1/chat/completions``.
    """

    def __init__(
        self,
        base_url: str,
        model: str = "",
        *,
        api_key: str | None = None,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.0,
        timeout: int = 60,
        **params: Any,
    ) -> None:
        super().__init__(model=model or "rest-target", system=system, max_tokens=max_tokens)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.temperature = temperature
        self.timeout = timeout
        self.params.update(params)
        self.name = model or base_url

    def _complete(self, messages: list[Message]) -> str:
        import requests  # kept lazy — not a hard dependency for offline use

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            **{k: v for k, v in self.params.items() if k not in ("model", "messages")},
        }
        resp = requests.post(
            f"{self.base_url}/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


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
