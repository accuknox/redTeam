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

    ``backend: rest``   — any OpenAI-compatible REST endpoint.
    ``backend: module`` — a Python file that defines ``invoke(prompt) -> str``.
    """
    spec = dict(spec)
    spec.pop("purpose", None)  # purpose lives on the config, not the provider
    backend = spec.pop("backend", None)
    if backend is None:
        return None  # type: ignore[return-value]  — caller checks for None
    if backend == "rest":
        url = spec.pop("url")
        model = spec.pop("model", "")
        return RestProvider(base_url=url, model=model, **spec)
    if backend == "module":
        module_path = spec.pop("module")
        return CallableProvider.from_module_path(module_path)
    raise ValueError(
        f"unknown target backend {backend!r} (expected rest | module)"
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
    generation: Generator
    grading: Judge
    plugins: list[RedteamPlugin]
    strategies: list[Strategy]
    raw: dict[str, Any]
    target: Provider | None = None


def load_config(path: "str | Path" = DEFAULT_CONFIG_PATH) -> RedTeamConfig:
    """Load and wire a `RedTeamConfig` from a YAML file."""
    data = yaml.safe_load(Path(path).read_text())

    purpose = data["target"]["purpose"]
    num_generations = int(data.get("num_generations", 5))
    concurrency = int(data.get("concurrency", 1))

    generation = build_generator(data["generation"])
    grading = build_judge(data["grading"])

    # `plugins` entries may be:
    #   - a string: plugin id or category key (expanded to all sub-plugins)
    #   - a dict with "dataset": a static-dataset plugin
    raw_entries = data.get("plugins", [])
    string_entries = [e for e in raw_entries if isinstance(e, str)]
    plugin_ids = resolve_plugin_ids(string_entries)
    plugins: list[RedteamPlugin | DatasetPlugin] = [
        get_plugin(pid, generation, purpose, num_tests=num_generations,
                   concurrency=concurrency)
        for pid in plugin_ids
    ]
    for entry in raw_entries:
        if isinstance(entry, dict) and "dataset" in entry:
            plugins.append(DatasetPlugin(
                dataset_path=entry["dataset"],
                detector_id=entry.get("detector", "prompt-injection"),
                purpose=purpose,
                column=entry.get("column"),
                category_column=entry.get("category_column", "category"),
                # `count` overrides the global num_generations per dataset, so a
                # dataset can sample e.g. 100 rows without changing LLM plugins.
                num_tests=int(entry.get("count", num_generations)),
                plugin_id=entry.get("id", "dataset"),
                sample=entry.get("sample", True),
            ))

    strategies: list[Strategy] = [
        get_strategy(s) for s in data.get("strategies", [])
    ]

    target_spec = data.get("target", {})
    target = build_target(target_spec) if target_spec.get("backend") else None

    return RedTeamConfig(
        purpose=purpose,
        num_generations=num_generations,
        concurrency=concurrency,
        generation=generation,
        grading=grading,
        plugins=plugins,
        strategies=strategies,
        raw=data,
        target=target,
    )
