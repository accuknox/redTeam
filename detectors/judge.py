"""Evaluator (LLM-as-a-judge) models.

A `Judge` is the model a detector uses to score the target's response against a
rubric. It is the evaluation-side counterpart to `plugins.Generator` (which
authors attacks) and `inference.Provider` (the target) — a separate role so the
attacker, the target, and the judge can run on independent backends.

`Judge` is a small inheritable base: a backend implements one `evaluate()` hook.
Judging benefits from deterministic, low-variance output, so the provided
backends default to low effort / low temperature / greedy decoding.

Backends provided:
  * AnthropicJudge   — hosted, via Anthropic SDK
  * MistralJudge     — hosted, via Mistral SDK
  * HuggingFaceJudge — local, via transformers
  * LocalJudge       — any OpenAI-compatible /v1/chat/completions endpoint
                       (e.g. a self-hosted gated evaluator)

Heavy dependencies (`anthropic`, `mistralai`, `transformers`, `torch`) are
imported lazily, so importing this module never requires them — you only pay for
the backend you instantiate. `LocalJudge` only requires `requests`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from typing import Any, Iterable


class Judge(ABC):
    """LLM-as-a-judge model. Subclass and implement `evaluate()`."""

    name: str = "judge"

    @abstractmethod
    def evaluate(self, prompt: str) -> str:
        """Return the judge model's verdict text for a grading prompt."""
        raise NotImplementedError


class ScriptedJudge(Judge):
    """Replays canned verdicts in order, so grading runs offline in tests."""

    name = "scripted"

    def __init__(self, verdicts: Iterable[str]) -> None:
        self._queue: deque[str] = deque(verdicts)

    def evaluate(self, prompt: str) -> str:
        if not self._queue:
            raise RuntimeError("ScriptedJudge ran out of scripted verdicts")
        return self._queue.popleft()


class AnthropicJudge(Judge):
    """LLM-as-a-judge via the Anthropic SDK (default `claude-opus-4-8`).

    Defaults to low effort for cheap, stable grading. Extra keyword args pass
    through to `messages.create`.
    """

    def __init__(
        self,
        model: str = "claude-opus-4-8",
        *,
        max_tokens: int = 1024,
        effort: str = "low",
        system: str | None = None,
        client: Any = None,
        api_key: str | None = None,
        **params: Any,
    ) -> None:
        import anthropic

        self.name = model
        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort
        self.system = system
        self.params = params
        self._client = client or anthropic.Anthropic(api_key=api_key)

    def evaluate(self, prompt: str) -> str:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "output_config": {"effort": self.effort},
            **self.params,
        }
        if self.system is not None:
            kwargs["system"] = self.system

        response = self._client.messages.create(**kwargs)
        return "".join(b.text for b in response.content if b.type == "text").strip()


class MistralJudge(Judge):
    """LLM-as-a-judge via the Mistral SDK (default `mistral-large-latest`).

    Defaults to `temperature=0` for deterministic grading. Extra keyword args
    pass through to `chat.complete`.
    """

    def __init__(
        self,
        model: str = "mistral-large-latest",
        *,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        system: str | None = None,
        client: Any = None,
        api_key: str | None = None,
        **params: Any,
    ) -> None:
        import os

        try:  # SDK layout differs across major versions
            from mistralai import Mistral
        except ImportError:  # mistralai >= 2.x moved the client under .client
            from mistralai.client import Mistral

        self.name = model
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.system = system
        self.params = params
        self._client = client or Mistral(api_key=api_key or os.environ.get("MISTRAL_API_KEY"))

    def evaluate(self, prompt: str) -> str:
        messages = []
        if self.system is not None:
            messages.append({"role": "system", "content": self.system})
        messages.append({"role": "user", "content": prompt})

        response = self._client.chat.complete(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            **self.params,
        )
        content = response.choices[0].message.content
        if isinstance(content, list):
            content = "".join(getattr(chunk, "text", "") or "" for chunk in content)
        return (content or "").strip()


class LocalJudge(Judge):
    """LLM-as-a-judge via any OpenAI-compatible /v1/chat/completions endpoint.

    Two grading modes, selected by ``gated``:

      * **rubric** (``gated=False``, the default) — for a *general* model
        (OpenRouter, vLLM, Ollama, …). `LLMDetector` builds the full rubric
        prompt (which instructs the model to emit ``{passed, score, reason}``)
        and sends it as one message. Use this for any ordinary chat model.

      * **gated** (``gated=True``) — for a *purpose-built* gated evaluator
        (e.g. ``redteam-evaluator-gated``) that already knows the protocol: the
        raw [user=attack, assistant=response] pair is sent with no rubric and
        the model returns ``{verdict, reason}`` directly.

    A general model in gated mode returns prose, not a verdict, which parses as
    "unparseable" and is scored as a break — so the default is rubric.

    Config example::

        grading:
          backend: custom
          base_url: https://openrouter.ai/api
          model: deepseek/deepseek-chat
          # gated: true        # only for a real gated evaluator endpoint
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        api_key: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        timeout: int = 30,
        gated: bool = False,
        **params: Any,
    ) -> None:
        self.name = model
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.gated = gated
        self.params = params
        self._session = None  # lazily built; reused so TLS/TCP setup is paid once

    def _get_session(self):
        """A pooled `requests.Session`, built once per judge.

        One grading call per case means the handshake cost was previously paid
        on every case in the run.
        """
        if self._session is None:
            import requests
            from requests.adapters import HTTPAdapter

            session = requests.Session()
            adapter = HTTPAdapter(pool_connections=32, pool_maxsize=64, max_retries=0)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._session = session
        return self._session

    def _call(self, messages: list[dict]) -> str:

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            **self.params,
        }
        # Accept bare host, /v1 root, or full endpoint without doubling the path.
        b = self.base_url
        url = (b if b.endswith("/chat/completions")
               else f"{b}/chat/completions" if b.endswith("/v1")
               else f"{b}/v1/chat/completions")
        resp = self._get_session().post(
            url,
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        # content is null when the model emits only reasoning / a tool call, hits
        # a filter, or refuses — coerce so callers always get a string.
        return resp.json()["choices"][0]["message"].get("content") or ""

    def evaluate(self, prompt: str) -> str:
        return self._call([{"role": "user", "content": prompt}])

    def evaluate_messages(self, messages: list[dict]) -> str:
        """Send a pre-built message list directly to the evaluator."""
        return self._call(messages)


class HuggingFaceJudge(Judge):
    """LLM-as-a-judge via a locally loaded Hugging Face causal LM.

    Defaults to greedy decoding (`do_sample=False`) for deterministic grading.
    Extra keyword args pass through to `model.generate`.
    """

    def __init__(
        self,
        model_id: str,
        *,
        max_new_tokens: int = 512,
        do_sample: bool = False,
        temperature: float = 1.0,
        top_p: float = 1.0,
        system: str | None = None,
        device_map: str | None = "auto",
        torch_dtype: Any = "auto",
        token: str | None = None,
        **generate_kwargs: Any,
    ) -> None:
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.name = model_id
        self.model_id = model_id
        self.max_new_tokens = max_new_tokens
        self.do_sample = do_sample
        self.temperature = temperature
        self.top_p = top_p
        self.system = system
        self.generate_kwargs = generate_kwargs

        self._tokenizer = AutoTokenizer.from_pretrained(model_id, token=token)
        self._model = AutoModelForCausalLM.from_pretrained(
            model_id, torch_dtype=torch_dtype, device_map=device_map, token=token
        )

    def evaluate(self, prompt: str) -> str:
        import torch

        messages = []
        if self.system is not None:
            messages.append({"role": "system", "content": self.system})
        messages.append({"role": "user", "content": prompt})

        if self._tokenizer.chat_template:
            inputs = self._tokenizer.apply_chat_template(
                messages, add_generation_prompt=True, return_tensors="pt", return_dict=True
            )
        else:
            text = f"{self.system}\n\n{prompt}" if self.system else prompt
            inputs = self._tokenizer(text, return_tensors="pt")
        inputs = {k: v.to(self._model.device) for k, v in inputs.items()}

        gen_kwargs: dict[str, Any] = {
            "max_new_tokens": self.max_new_tokens,
            "do_sample": self.do_sample,
            "pad_token_id": self._tokenizer.pad_token_id or self._tokenizer.eos_token_id,
            **self.generate_kwargs,
        }
        if self.do_sample:
            gen_kwargs.update(temperature=self.temperature, top_p=self.top_p)

        prompt_len = inputs["input_ids"].shape[-1]
        with torch.no_grad():
            output = self._model.generate(**inputs, **gen_kwargs)

        new_tokens = output[0][prompt_len:]
        return self._tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
