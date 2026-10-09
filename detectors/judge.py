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
  * BedrockJudge     — hosted, any Amazon Bedrock model via boto3 Converse
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

from detectors.schema import JSON_OBJECT_FORMAT as _JSON_OBJECT


class Judge(ABC):
    """LLM-as-a-judge model. Subclass and implement `evaluate()`."""

    name: str = "judge"

    #: True when this backend can be asked for schema-constrained output, i.e.
    #: `evaluate()` accepts a `response_format` keyword. Callers check this flag
    #: rather than inspecting the signature, so a user-defined `Judge` written
    #: against the original one-argument `evaluate()` keeps working untouched.
    supports_schema: bool = False

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
    """LLM-as-a-judge via the Mistral SDK (default `mistral-large-2512`).

    Defaults to `temperature=0` for deterministic grading. Extra keyword args
    pass through to `chat.complete`.
    """

    supports_schema = True

    def __init__(
        self,
        model: str = "mistral-large-2512",
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
        # Flipped off permanently on the first rejection — see LocalJudge.
        self._schema_supported = True

    def evaluate(self, prompt: str, *, response_format: dict | None = None) -> str:
        messages = []
        if self.system is not None:
            messages.append({"role": "system", "content": self.system})
        messages.append({"role": "user", "content": prompt})

        # Mistral takes `{"type": "json_object"}` across its range, including the
        # small models; a full json_schema is not universally available, so the
        # weaker constraint is used. It still removes fences and prose, which is
        # where most small-model grading failures come from.
        want_json = response_format is not None and self._schema_supported
        try:
            content = self._complete(messages, _JSON_OBJECT if want_json else None)
        except Exception:  # noqa: BLE001 — any rejection means "unsupported"
            if not want_json:
                raise
            self._schema_supported = False
            content = self._complete(messages, None)

        if isinstance(content, list):
            content = "".join(getattr(chunk, "text", "") or "" for chunk in content)
        return (content or "").strip()

    def _complete(self, messages: list[dict], response_format: dict | None):
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            **self.params,
        }
        if response_format is not None:
            kwargs["response_format"] = response_format
        return self._client.chat.complete(**kwargs).choices[0].message.content


class BedrockJudge(Judge):
    """LLM-as-a-judge via Amazon Bedrock's Converse API (any hosted model family).

    `model` is a Bedrock model id, inference profile, or ARN. Credentials
    resolve as in `inference.provider.bedrock_client`: `api_key` (a Bedrock API
    key), explicit AWS keys, `profile`, then the default AWS chain. Defaults to
    `temperature=0` for deterministic grading; extra keyword args pass through
    to `converse` (e.g. `additionalModelRequestFields`).

    Config example::

        grading:
          backend: bedrock
          model: us.anthropic.claude-sonnet-4-20250514-v1:0
          region: us-east-1
    """

    supports_schema = True

    def __init__(
        self,
        model: str,
        *,
        region: str | None = None,
        api_key: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        profile: str | None = None,
        endpoint_url: str | None = None,
        max_tokens: int = 1024,
        temperature: float | None = 0.0,
        system: str | None = None,
        client: Any = None,
        **params: Any,
    ) -> None:
        from inference.provider import bedrock_client

        self.name = model
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.system = system
        self.params = params
        self._client = client or bedrock_client(
            region=region, api_key=api_key,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            profile=profile, endpoint_url=endpoint_url,
        )
        # Flipped off permanently on the first rejection — see LocalJudge.
        self._schema_supported = True

    def evaluate(self, prompt: str, *, response_format: dict | None = None) -> str:
        output_config = _converse_output_config(response_format) if self._schema_supported else None
        if output_config is None:
            return self._converse(prompt, None)
        try:
            return self._converse(prompt, output_config)
        except Exception as exc:  # noqa: BLE001 — narrowed below
            # Only a rejected *request* means "no structured output for this
            # model". Throttling or an outage must not disable it for the run.
            from botocore.exceptions import ClientError, ParamValidationError

            rejected = isinstance(exc, ParamValidationError) or (
                isinstance(exc, ClientError)
                and exc.response.get("Error", {}).get("Code") == "ValidationException"
            )
            if not rejected:
                raise
            self._schema_supported = False
            return self._converse(prompt, None)

    def _converse(self, prompt: str, output_config: dict | None) -> str:
        from inference.provider import converse_text

        inference: dict[str, Any] = {"maxTokens": self.max_tokens}
        if self.temperature is not None:
            inference["temperature"] = self.temperature
        kwargs: dict[str, Any] = {
            "modelId": self.model,
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            "inferenceConfig": inference,
            **self.params,
        }
        if self.system is not None:
            kwargs["system"] = [{"text": self.system}]
        if output_config is not None:
            kwargs["outputConfig"] = output_config
        return converse_text(self._client.converse(**kwargs)).strip()


def _converse_output_config(response_format: dict | None) -> dict | None:
    """Translate an OpenAI-style `json_schema` response_format into Converse's
    `outputConfig`. Anything else (none, `json_object`) has no Converse
    equivalent and is sent unconstrained."""
    import json as _json

    if not response_format or response_format.get("type") != "json_schema":
        return None
    spec = response_format.get("json_schema") or {}
    return {
        "textFormat": {
            "type": "json_schema",
            "structure": {
                "jsonSchema": {
                    "name": spec.get("name", "response"),
                    "schema": _json.dumps(spec.get("schema", {})),
                }
            },
        }
    }


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

    Asks for schema-constrained output when the caller supplies a
    `response_format`, which is what makes an 8B-class judge usable: the decoder
    cannot emit a fence, a preamble, or a verdict outside the allowed set. A
    backend that rejects it is detected once and the run continues unconstrained.
    """

    supports_schema = True

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        api_key: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        timeout: int = 180,
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
        # Flipped off permanently the first time the backend rejects a schema, so
        # an unsupporting endpoint costs one failed request, not one per case.
        self._schema_supported = True

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

    def _call(self, messages: list[dict], response_format: dict | None = None) -> str:
        """POST one chat completion, degrading once if the schema is rejected.

        Backends differ (vLLM, llama.cpp, Ollama, hosted APIs), so a rejection
        must cost one request for the whole run rather than one per case — and
        must never fail the run, since the prompt-only path still parses.
        """
        if response_format is not None and self._schema_supported:
            try:
                return self._post(messages, response_format)
            except Exception:  # noqa: BLE001 — any rejection means "unsupported"
                self._schema_supported = False
        return self._post(messages, None)

    def _post(self, messages: list[dict], response_format: dict | None) -> str:

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
        if response_format is not None:
            payload["response_format"] = response_format
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

    def evaluate(self, prompt: str, *, response_format: dict | None = None) -> str:
        return self._call([{"role": "user", "content": prompt}], response_format)

    def evaluate_messages(
        self, messages: list[dict], *, response_format: dict | None = None
    ) -> str:
        """Send a pre-built message list directly to the evaluator."""
        return self._call(messages, response_format)


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
