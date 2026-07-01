"""Configuration loader.

Reads `config.yaml` and distributes its values to the components that need them:

  * `generation` -> a `Generator` (plugins/generators.py) used to author attacks.
  * `grading`    -> a `Judge` (detectors/judge.py) used by detectors to evaluate
    responses (LLM-as-a-judge).
  * `target.purpose`, `num_generations`, `plugins` -> the plugins, each wired
    with the generation model, the target purpose, and the generation count.

`build_generator()` / `build_judge()` are the single places that map a
`backend:` string to the concrete class, so adding a backend means one new
branch in each.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from plugins import (
    AnthropicGenerator,
    DatasetPlugin,
    Generator,
    HuggingFaceGenerator,
    MistralGenerator,
    RedteamPlugin,
    get_plugin,
    resolve_plugin_ids,
)
from strategies import Strategy, get_strategy
from detectors import (
    AnthropicJudge,
    HuggingFaceJudge,
    Judge,
    LocalJudge,
    MistralJudge,
)
from inference import CallableProvider, Provider, RestProvider

DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.yaml")


def build_generator(spec: dict[str, Any]) -> Generator:
    """Build a generation/grading model from a config block.

    `backend` selects the class; `model` is the model id/name; every other key
    passes straight through as a keyword argument to that backend.
    """
    spec = dict(spec)
    backend = spec.pop("backend", "anthropic")
    model = spec.pop("model")
    if backend == "anthropic":
        return AnthropicGenerator(model, **spec)
    if backend == "mistral":
        return MistralGenerator(model, **spec)
    if backend == "huggingface":
        return HuggingFaceGenerator(model, **spec)
    raise ValueError(
        f"unknown generator backend {backend!r} (expected anthropic | mistral | huggingface)"
    )


def build_target(spec: dict[str, Any]) -> Provider:
    """Build a target provider from a config block.

    ``type: rest``      any OpenAI-compatible REST endpoint (name = base URL).
    ``type: openai``    OpenAI API (name = model name, e.g. gpt-4o).
    ``type: function``  Python callable (name = module#fn).
    """
    spec = dict(spec)
    spec.pop("purpose", None)
    target_type = spec.pop("type", None)
    if target_type is None:
        return None  # type: ignore[return-value]  — caller checks for None
    if target_type == "rest":
        # config file path takes precedence over inline spec
        config_file = spec.pop("config", None)
        if config_file:
            return RestProvider.from_config_file(config_file, api_key=spec.get("api_key"))
        url = spec.pop("name", spec.pop("url", None))
        if not url:
            raise ValueError("target type 'rest' requires 'name' (base URL) or 'config' (file path)")
        model = spec.pop("model", "")
        req_template = spec.pop("request", None)
        response_field = spec.pop("response_field", None)
        extra_headers = spec.pop("headers", {})
        return RestProvider(
            base_url=url, model=model,
            req_template=req_template, response_field=response_field,
            extra_headers=extra_headers, **spec,
        )
    if target_type == "openai":
        model = spec.pop("name", spec.pop("model", ""))
        return RestProvider(base_url="https://api.openai.com", model=model, **spec)
    if target_type == "function":
        fn_spec = spec.pop("name", None)
        if not fn_spec:
            raise ValueError("target type 'function' requires 'name' (module#fn)")
        return CallableProvider.from_module_spec(fn_spec)
    raise ValueError(
        f"unknown target type {target_type!r} (expected rest | openai | function)"
    )


def build_judge(spec: dict[str, Any]) -> Judge:
    """Build an evaluator (LLM-as-a-judge) model from a config block.

    `backend` selects the class; `model` is the model id/name; every other key
    passes straight through as a keyword argument to that backend.
    """
    spec = dict(spec)
    backend = spec.pop("backend", "anthropic")
    model = spec.pop("model")
    if backend == "anthropic":
        return AnthropicJudge(model, **spec)
    if backend == "mistral":
        return MistralJudge(model, **spec)
    if backend == "huggingface":
        return HuggingFaceJudge(model, **spec)
    if backend == "local":
        url = spec.pop("url")
        return LocalJudge(base_url=url, model=model, **spec)
    raise ValueError(
        f"unknown judge backend {backend!r} (expected anthropic | mistral | huggingface | local)"
    )


@dataclass
class RedTeamConfig:
    """Fully-wired run configuration."""

    purpose: str
    num_generations: int
    concurrency: int
    delay_ms: int
    generation: Generator
    grading: Judge
    plugins: list[RedteamPlugin]
    strategies: list[Strategy]
    raw: dict[str, Any]
    target: Provider | None = None


def load_config(path: "str | Path" = DEFAULT_CONFIG_PATH) -> RedTeamConfig:
    """Load and wire a `RedTeamConfig` from a YAML or JSON file."""
    data = yaml.safe_load(Path(path).read_text())

    purpose = data["target"]["purpose"]
    num_generations = int(data.get("num_generations", 5))
    concurrency = int(data.get("concurrency", 1))
    delay_ms = int(data.get("delay", 0) or 0)

    generation = build_generator(data["generation"])
    grading = build_judge(data["grading"])

    # Global options injected into every plugin's meta-prompt.
    global_instructions: str = data.get("generation_instructions", "") or ""
    global_language: str = data.get("language", "") or ""
    global_max_chars: int = int(data.get("max_chars_per_message", 0) or 0)

    # `plugins` entries may be:
    #   - a string: plugin id or category key (expanded to all sub-plugins)
    #   - a dict with "id": per-plugin overrides (num_tests, severity, examples, ...)
    #   - a dict with "dataset": a static-dataset plugin
    raw_entries = data.get("plugins", [])

    plugins: list[RedteamPlugin | DatasetPlugin] = []

    for entry in raw_entries:
        if isinstance(entry, str):
            # String form — expand categories and use all global defaults.
            for pid in resolve_plugin_ids([entry]):
                plugins.append(
                    get_plugin(pid, generation, purpose,
                               num_tests=num_generations,
                               generation_instructions=global_instructions,
                               language=global_language,
                               max_chars=global_max_chars,
                               concurrency=concurrency)
                )

        elif isinstance(entry, dict) and "dataset" in entry:
            # Static dataset plugin — loads prompts from a file.
            plugins.append(DatasetPlugin(
                dataset_path=entry["dataset"],
                detector_id=entry.get("detector", "prompt-injection"),
                purpose=purpose,
                column=entry.get("column"),
                category_column=entry.get("category_column", "category"),
                # `count` overrides the global num_generations per dataset.
                num_tests=int(entry.get("count", num_generations)),
                plugin_id=entry.get("id", "dataset"),
                sample=entry.get("sample", True),
            ))

        elif isinstance(entry, dict) and "id" in entry:
            # Dict form — per-plugin overrides.
            # A category key in `id` expands to all its sub-plugins, each
            # inheriting the same overrides.
            pid_or_cat = entry["id"]
            per_num      = int(entry.get("num_tests", num_generations))
            per_sev      = str(entry.get("severity", ""))
            per_ex       = str(entry.get("examples", ""))
            per_instr    = str(entry.get("generation_instructions", global_instructions))
            per_lang     = str(entry.get("language", global_language))
            per_max_chars = int(entry.get("max_chars", global_max_chars) or 0)
            for pid in resolve_plugin_ids([pid_or_cat]):
                plugins.append(
                    get_plugin(pid, generation, purpose,
                               num_tests=per_num,
                               severity=per_sev,
                               examples=per_ex or None,
                               generation_instructions=per_instr,
                               language=per_lang,
                               max_chars=per_max_chars,
                               concurrency=concurrency)
                )

    strategies: list[Strategy] = [
        get_strategy(s) for s in data.get("strategies", [])
    ]

    target_spec = data.get("target", {})
    target = build_target(target_spec) if target_spec.get("type") else None

    return RedTeamConfig(
        purpose=purpose,
        num_generations=num_generations,
        concurrency=concurrency,
        delay_ms=delay_ms,
        generation=generation,
        grading=grading,
        plugins=plugins,
        strategies=strategies,
        raw=data,
        target=target,
    )
