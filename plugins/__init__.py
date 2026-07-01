"""Plugin layer: authoring adversarial test prompts.

Owns generation end to end — the generation-model abstraction (`Generator`), the
`RedteamPlugin` base, and the plugin taxonomy:

  * high-level **category modules** — `security`, `privacy`, `harmful`,
    `criminal`, `trust` — each grouping 5 specific sub-plugins.
  * `CATEGORIES` maps a category key -> its plugin ids.
  * `get_plugin()` builds one plugin by id; `resolve_plugin_ids()` expands a mix
    of category keys and plugin ids (as used by a config file).
"""

from __future__ import annotations

from typing import Any

from plugins.base import Generator, ScriptedGenerator, RedteamPlugin, DatasetPlugin, TestCase, is_basic_refusal
from plugins.category import CategoryPlugin
from plugins.generators import AnthropicGenerator, MistralGenerator, HuggingFaceGenerator
from plugins import security, privacy, harmful, criminal, trust, jailbreak, deception, code
from plugins.security import PromptInjectionPlugin

# High-level category modules, in run order.
_CATEGORY_MODULES = [security, privacy, harmful, criminal, trust, jailbreak, deception, code]

#: category key -> list of plugin ids in that category.
CATEGORIES: dict[str, list[str]] = {}
#: plugin id -> plugin class.
_REGISTRY: dict[str, type[RedteamPlugin]] = {}
#: plugin id -> category key (the reverse of CATEGORIES).
_PLUGIN_CATEGORY: dict[str, str] = {}
#: category key -> human-readable label (e.g. "harmful" -> "Harmful Content").
CATEGORY_LABELS: dict[str, str] = {}

for _mod in _CATEGORY_MODULES:
    _ids: list[str] = []
    _label = ""
    for _cls in _mod.PLUGINS:
        _REGISTRY[_cls.id] = _cls
        _PLUGIN_CATEGORY[_cls.id] = _mod.CATEGORY
        _ids.append(_cls.id)
        # The human-readable label lives on the CategoryPlugin base; flat plugins
        # (e.g. PromptInjectionPlugin) lack it, so take the first one we find.
        if not _label:
            _label = getattr(_cls, "category", "") or ""
    CATEGORIES[_mod.CATEGORY] = _ids
    CATEGORY_LABELS[_mod.CATEGORY] = _label or _mod.CATEGORY


def get_plugin(
    plugin_id: str,
    generator: Generator,
    purpose: str,
    *,
    num_tests: int = 5,
    severity: str = "",
    generation_instructions: str = "",
    language: str = "",
    max_chars: int = 0,
    **kwargs: Any,
) -> RedteamPlugin:
    """Resolve a plugin id to an instance wired with its generation model."""
    try:
        cls = _REGISTRY[plugin_id]
    except KeyError:
        raise KeyError(
            f"no plugin registered for id {plugin_id!r}; known: {sorted(_REGISTRY)}"
        ) from None
    return cls(
        generator, purpose,
        num_tests=num_tests,
        severity=severity,
        generation_instructions=generation_instructions,
        language=language,
        max_chars=max_chars,
        **kwargs,
    )


def resolve_plugin_ids(entries: list[str]) -> list[str]:
    """Expand a list of config entries (category keys and/or plugin ids) into a
    de-duplicated list of concrete plugin ids."""
    resolved: list[str] = []
    for entry in entries:
        if entry in CATEGORIES:
            resolved.extend(CATEGORIES[entry])
        elif entry in _REGISTRY:
            resolved.append(entry)
        else:
            raise KeyError(
                f"unknown plugin/category {entry!r}; "
                f"categories={sorted(CATEGORIES)}, plugins={sorted(_REGISTRY)}"
            )
    seen: set[str] = set()
    return [pid for pid in resolved if not (pid in seen or seen.add(pid))]


def all_plugin_ids() -> list[str]:
    return list(_REGISTRY)


def category_for_plugin(plugin_id: str, detector_id: str = "") -> tuple[str, str]:
    """Map a finding to its `(category_key, category_label)` in the taxonomy.

    Resolves by `plugin_id` first (LLM plugins use a taxonomy id directly).
    Static dataset plugins may carry a custom `plugin_id` (e.g. `toxic-chat`)
    while routing to a taxonomy grader, so we fall back to `detector_id` — which
    must be a registered taxonomy id to be graded. This keeps dataset-backed
    findings labelled under the same plugin categories as the LLM-generated ones.
    """
    key = _PLUGIN_CATEGORY.get(plugin_id) or _PLUGIN_CATEGORY.get(detector_id)
    if key is None:
        raise KeyError(
            f"cannot map plugin_id={plugin_id!r} / detector_id={detector_id!r} "
            f"to a category; known plugin ids: {sorted(_PLUGIN_CATEGORY)}"
        )
    return key, CATEGORY_LABELS[key]


__all__ = [
    "Generator",
    "ScriptedGenerator",
    "AnthropicGenerator",
    "MistralGenerator",
    "HuggingFaceGenerator",
    "RedteamPlugin",
    "DatasetPlugin",
    "CategoryPlugin",
    "TestCase",
    "is_basic_refusal",
    "PromptInjectionPlugin",
    "CATEGORIES",
    "CATEGORY_LABELS",
    "get_plugin",
    "resolve_plugin_ids",
    "all_plugin_ids",
    "category_for_plugin",
]
