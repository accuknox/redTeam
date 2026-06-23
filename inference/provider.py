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

from abc import ABC, abstractmethod
from collections import deque
from typing import Any, Iterable

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
