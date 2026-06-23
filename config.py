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
    Strategy,
    get_plugin,
    get_strategy,
    resolve_plugin_ids,
)
from detectors import (
    AnthropicJudge,
    HuggingFaceJudge,
    Judge,
    LocalJudge,
    MistralJudge,
)

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
                num_tests=num_generations,
                plugin_id=entry.get("id", "dataset"),
                sample=entry.get("sample", True),
            ))

    strategies: list[Strategy] = [
        get_strategy(s) for s in data.get("strategies", [])
    ]

    return RedTeamConfig(
        purpose=purpose,
        num_generations=num_generations,
        concurrency=concurrency,
        generation=generation,
        grading=grading,
        plugins=plugins,
        strategies=strategies,
        raw=data,
    )
