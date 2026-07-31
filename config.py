"""Configuration loader.

Reads `config.yaml` and distributes its values to the components that need them:

  * `generation` -> a `Generator` (plugins/generators.py) used to author attacks.
  * `grading`    -> a `Judge` (detectors/judge.py) used by detectors to evaluate
    responses (LLM-as-a-judge).
  * `target.purpose`, `num_tests`, `plugins` -> the plugins, each wired
    with the generation model, the target purpose, and the generation count.

`build_generator()` / `build_judge()` are the single places that map a
`backend:` string to the concrete class, so adding a backend means one new
branch in each.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from plugins import (
    AnthropicGenerator,
    DatasetPlugin,
    Generator,
    HuggingFaceGenerator,
    MistralGenerator,
    OpenAIGenerator,
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
from inference import (
    AnthropicProvider,
    CallableProvider,
    MistralProvider,
    Provider,
    RestProvider,
)

DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.yaml")


def _parse_json_flexible(obj: Any) -> Any:
    """Parse JSON string or object. Converts single quotes to double quotes.

    Allows users to paste {'key': 'value'} (with single quotes) without escaping.
    Returns the parsed object or the original if it's already an object.
    """
    if not isinstance(obj, str):
        return obj  # already an object

    import json
    try:
        # Convert single quotes to double quotes if no double quotes present
        if "'" in obj and '"' not in obj:
            obj = obj.replace("'", '"')
        return json.loads(obj)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")


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
    if backend in ("openai", "custom"):
        return OpenAIGenerator(model, **spec)
    raise ValueError(
        f"unknown generator backend {backend!r} (expected anthropic | mistral | huggingface | openai | custom)"
    )


def build_target(spec: dict[str, Any]) -> Provider:
    """Build a target provider from a config block.

    ``type: openai``     OpenAI API (name = model name, e.g. gpt-4o).
    ``type: custom``     OpenAI-compatible endpoint (vLLM, Ollama, LM Studio; name = base URL).
    ``type: rest``       Generic REST endpoint with custom request/response templates.
    ``type: anthropic``  Anthropic API (Claude models).
    ``type: mistral``    Mistral API (Mistral models).
    ``type: function``   Python callable (name = module#fn).
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

        # Parse JSON strings with flexible quote handling
        if req_template:
            req_template = _parse_json_flexible(req_template)
        if extra_headers:
            extra_headers = _parse_json_flexible(extra_headers)

        return RestProvider(
            base_url=url, model=model,
            req_template=req_template, response_field=response_field,
            extra_headers=extra_headers, **spec,
        )
    if target_type == "openai":
        model = spec.pop("name", spec.pop("model", ""))
        return RestProvider(base_url="https://api.openai.com", model=model, **spec)
    if target_type == "custom":
        # Custom OpenAI-compatible endpoint (vLLM, Ollama, LM Studio, etc.)
        url = spec.pop("base_url", None)
        if not url:
            raise ValueError("target type 'custom' requires 'base_url' (base URL)")
        model = spec.pop("model", "")
        return RestProvider(base_url=url, model=model, **spec)
    if target_type == "anthropic":
        model = spec.pop("name", spec.pop("model", "claude-opus-4-8"))
        return AnthropicProvider(model=model, **spec)
    if target_type == "mistral":
        model = spec.pop("name", spec.pop("model", "mistral-large-latest"))
        return MistralProvider(model=model, **spec)
    if target_type == "function":
        fn_spec = spec.pop("name", None)
        if not fn_spec:
            raise ValueError("target type 'function' requires 'name' (module#fn)")
        return CallableProvider.from_module_spec(fn_spec)
    raise ValueError(
        f"unknown target type {target_type!r} (expected rest | openai | custom | anthropic | mistral | function)"
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
    if backend == "local" or backend == "custom":
        url = spec.pop("url", None) or spec.pop("base_url", None)
        if not url:
            raise ValueError(f"{backend} judge requires a 'url' or 'base_url' key")
        return LocalJudge(base_url=url, model=model, **spec)
    raise ValueError(
        f"unknown judge backend {backend!r} (expected anthropic | mistral | huggingface | local | custom)"
    )


@dataclass
class RedTeamConfig:
    """Fully-wired run configuration."""

    purpose: str
    num_tests: int
    concurrency: int
    delay_ms: int
    generation: Generator
    grading: Judge
    plugins: list[RedteamPlugin]
    strategies: list[Strategy]
    raw: dict[str, Any]
    target: Provider | None = None
    targets: list[Provider] = field(default_factory=list)  # all targets; len>1 = multi-target run
    save_prompts: str | None = None   # path to write generated prompts JSONL
    load_prompts: str | None = None   # path to read cached prompts JSONL


def load_config(path: "str | Path" = DEFAULT_CONFIG_PATH) -> RedTeamConfig:
    """Load and wire a `RedTeamConfig` from a YAML or JSON file."""
    data = yaml.safe_load(Path(path).read_text())

    # purpose: top-level key takes precedence; falls back to target.purpose for
    # backwards compatibility with single-target configs.
    purpose = (
        data.get("purpose")
        or data.get("target", {}).get("purpose")
        or ""
    )
    if not purpose:
        raise ValueError("'purpose' is required — set it at the top level or under 'target:'")
    num_tests = int(data.get("num_tests", data.get("num_generations", 5)))
    concurrency = int(data.get("concurrency", 1))
    delay_ms = int(data.get("delay", 0) or 0)

    generation = build_generator(data["generation"])
    grading = build_judge(data["grading"])

    # Global options injected into every plugin's meta-prompt.
    global_instructions: str = data.get("generation_instructions", "") or ""
    global_language: str = data.get("language", "") or ""
    global_max_chars: int = int(data.get("max_chars_per_message", 0) or 0)
    global_severity: str = str(data.get("severity", "") or "")
    global_examples: str = str(data.get("examples", "") or "")

    # `plugins` entries may be:
    #   - a string: plugin id or category key (expanded to all sub-plugins)
    #   - a dict with "id": per-plugin overrides (num_tests, severity, examples, ...)
    #   - a dict with "dataset": a static-dataset plugin
    raw_entries = data.get("plugins", [])

    plugins: list[RedteamPlugin | DatasetPlugin] = []

    for entry in raw_entries:
        if isinstance(entry, str):
            # String form — expand frameworks/categories and use all global defaults.
            for pid in resolve_plugin_ids([entry]):
                plugins.append(
                    get_plugin(pid, generation, purpose,
                               num_tests=num_tests,
                               severity=global_severity,
                               examples=global_examples or None,
                               generation_instructions=global_instructions,
                               language=global_language,
                               max_chars=global_max_chars,
                               concurrency=concurrency)
                )

        elif isinstance(entry, dict) and "id" in entry:
            pid_or_cat = entry["id"]

            if "dataset" in entry:
                # Per-plugin static dataset — skip LLM generation, use the file instead.
                # `id` doubles as both plugin_id and detector_id so grading is automatic.
                plugins.append(DatasetPlugin(
                    dataset_path=entry["dataset"],
                    detector_id=pid_or_cat,
                    purpose=purpose,
                    column=entry.get("column"),
                    category_column=entry.get("category_column", "category"),
                    num_tests=int(c) if (c := entry.get("count", entry.get("num_tests"))) is not None else None,
                    plugin_id=pid_or_cat,
                    severity=str(entry.get("severity", "")),
                    sample=entry.get("sample", True),
                ))
            else:
                # LLM generation — per-plugin overrides.
                per_num       = int(entry.get("num_tests", num_tests))
                per_sev       = str(entry.get("severity", global_severity))
                per_ex        = str(entry.get("examples", global_examples))
                per_instr     = str(entry.get("generation_instructions", global_instructions))
                per_lang      = str(entry.get("language", global_language))
                per_max_chars = int(entry.get("max_chars", global_max_chars) or 0)
                per_strats    = [get_strategy(s) for s in entry.get("strategies", [])]

                if pid_or_cat.startswith("custom:"):
                    # Custom plugin — user supplies the adversarial objective directly.
                    from plugins.custom import CustomPlugin
                    objective = str(entry.get("objective", ""))
                    if not objective:
                        raise ValueError(
                            f"plugin {pid_or_cat!r} starts with 'custom:' but has no 'objective' key"
                        )
                    plugins.append(CustomPlugin(
                        generation, purpose,
                        plugin_id=pid_or_cat,
                        objective=objective,
                        frameworks=list(entry.get("frameworks", [])),
                        controls=list(entry.get("controls", [])),
                        num_tests=per_num,
                        severity=per_sev,
                        examples=per_ex,
                        generation_instructions=per_instr,
                        language=per_lang,
                        max_chars=per_max_chars,
                        concurrency=concurrency,
                        strategies=per_strats,
                    ))
                else:
                    # A category/framework key in `id` expands to all its sub-plugins.
                    for pid in resolve_plugin_ids([pid_or_cat]):
                        plugins.append(
                            get_plugin(pid, generation, purpose,
                                       num_tests=per_num,
                                       severity=per_sev,
                                       examples=per_ex or None,
                                       generation_instructions=per_instr,
                                       language=per_lang,
                                       max_chars=per_max_chars,
                                       concurrency=concurrency,
                                       strategies=per_strats)
                        )

        elif isinstance(entry, dict) and "dataset" in entry:
            # Standalone dataset plugin — no id: key, detector: is required.
            _detector = entry.get("detector")
            if not _detector:
                raise ValueError(
                    f"dataset entry '{entry.get('dataset')}' is missing a 'detector:' key — "
                    "set it to the plugin id whose grader should evaluate these prompts "
                    "(e.g. detector: sql-injection), or add a category_column to the file."
                )
            plugins.append(DatasetPlugin(
                dataset_path=entry["dataset"],
                detector_id=_detector,
                purpose=purpose,
                column=entry.get("column"),
                category_column=entry.get("category_column", "category"),
                num_tests=int(c) if (c := entry.get("count", entry.get("num_tests"))) is not None else None,
                plugin_id=entry.get("id", "dataset"),
                severity=str(entry.get("severity", "")),
                sample=entry.get("sample", True),
            ))

    strategies: list[Strategy] = [
        get_strategy(s) for s in data.get("strategies", [])
    ]

    # Resolve target(s).
    # `targets:` (plural) enables multi-target / A-B comparison runs.
    # `target:`  (singular) is the original single-target form — still fully supported.
    # Either way, RedTeamConfig.targets is always a list; .target is the first entry.
    raw_targets = data.get("targets")  # plural — list of target specs
    if raw_targets:
        targets: list[Provider] = []
        for i, t_spec in enumerate(raw_targets):
            t_spec = dict(t_spec)
            label = t_spec.pop("label", t_spec.get("name", f"target-{i + 1}"))
            t_spec.pop("purpose", None)          # purpose is global in multi-target mode
            provider = build_target(t_spec)
            if provider:
                provider.name = label            # label is what appears in output
                targets.append(provider)
        target = targets[0] if targets else None
    else:
        # single-target backwards compat
        target_spec = data.get("target", {})
        target = build_target(target_spec) if target_spec.get("type") else None
        targets = [target] if target else []

    return RedTeamConfig(
        purpose=purpose,
        num_tests=num_tests,
        concurrency=concurrency,
        delay_ms=delay_ms,
        generation=generation,
        grading=grading,
        plugins=plugins,
        strategies=strategies,
        raw=data,
        target=target,
        targets=targets,
        save_prompts=data.get("save_prompts") or None,
        load_prompts=data.get("load_prompts") or None,
    )
