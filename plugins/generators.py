"""Concrete generation backends for plugins.

Several ways to drive the attack-authoring model, all implementing the
`Generator.complete(prompt) -> str` contract so plugins are agnostic to which is
used:

  * `AnthropicGenerator`   — a hosted model via the Anthropic SDK.
  * `MistralGenerator`     — a hosted model via the Mistral SDK.
  * `HuggingFaceGenerator` — a model loaded locally from the Hugging Face Hub.

Heavy dependencies (`anthropic`, `mistralai`, `transformers`, `torch`) are
imported lazily inside `__init__`, so importing this module — and the rest of
`plugins` — never requires them. You only pay for the backend you instantiate.
"""

from __future__ import annotations

from typing import Any

from plugins.base import Generator


class AnthropicGenerator(Generator):
    """Generation via the Anthropic SDK.

    Defaults to `claude-opus-4-8` and steers cost/quality with `effort` rather
    than a thinking budget. Set `use_thinking=True` to enable adaptive thinking
    for harder generation. Extra keyword args pass straight through to
    `messages.create` (e.g. backend params you want to expand with later).
    """

    def __init__(
        self,
        model: str = "claude-opus-4-8",
        *,
        max_tokens: int = 4096,
        effort: str = "medium",
        use_thinking: bool = False,
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
        self.use_thinking = use_thinking
        self.system = system
        self.params = params
        self._client = client or anthropic.Anthropic(api_key=api_key)

    def complete(self, prompt: str) -> str:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "output_config": {"effort": self.effort},
            **self.params,
        }
        if self.system is not None:
            kwargs["system"] = self.system
        if self.use_thinking:
            kwargs["thinking"] = {"type": "adaptive"}

        response = self._client.messages.create(**kwargs)
        return "".join(b.text for b in response.content if b.type == "text").strip()


class MistralGenerator(Generator):
    """Generation via the Mistral SDK.

    Defaults to `mistral-large-latest`. Extra keyword args pass straight through
    to `chat.complete` (e.g. `top_p`, `random_seed`) so the backend can be
    expanded without changing this surface.
    """

    def __init__(
        self,
        model: str = "mistral-large-latest",
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
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

    def complete(self, prompt: str) -> str:
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
        # The SDK returns a str for plain completions, or a list of content
        # chunks; normalize both to text.
        if isinstance(content, list):
            content = "".join(
                getattr(chunk, "text", "") or "" for chunk in content
            )
        return (content or "").strip()


class HuggingFaceGenerator(Generator):
    """Generation via a locally loaded Hugging Face causal LM.

    Loads tokenizer + weights once at construction (the expensive step), then
    `complete()` runs generation. Instruct/chat models are fed through the
    tokenizer's chat template when one is available; otherwise the prompt is
    encoded directly. Extra keyword args pass through to `model.generate`.
    """

    def __init__(
        self,
        model_id: str,
        *,
        max_new_tokens: int = 512,
        temperature: float = 0.9,
        top_p: float = 0.95,
        do_sample: bool = True,
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
        self.temperature = temperature
        self.top_p = top_p
        self.do_sample = do_sample
        self.system = system
        self.generate_kwargs = generate_kwargs

        self._tokenizer = AutoTokenizer.from_pretrained(model_id, token=token)
        self._model = AutoModelForCausalLM.from_pretrained(
            model_id, torch_dtype=torch_dtype, device_map=device_map, token=token
        )

    def complete(self, prompt: str) -> str:
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
