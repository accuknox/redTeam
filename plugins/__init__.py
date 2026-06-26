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

for _mod in _CATEGORY_MODULES:
    _ids: list[str] = []
    for _cls in _mod.PLUGINS:
        _REGISTRY[_cls.id] = _cls
        _ids.append(_cls.id)
    CATEGORIES[_mod.CATEGORY] = _ids


def get_plugin(
    plugin_id: str,
    generator: Generator,
    purpose: str,
    *,
    num_tests: int = 5,
    **kwargs: Any,
) -> RedteamPlugin:
    """Resolve a plugin id to an instance wired with its generation model."""
    try:
        cls = _REGISTRY[plugin_id]
    except KeyError:
        raise KeyError(
            f"no plugin registered for id {plugin_id!r}; known: {sorted(_REGISTRY)}"
        ) from None
    return cls(generator, purpose, num_tests=num_tests, **kwargs)


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
    "get_plugin",
    "resolve_plugin_ids",
    "all_plugin_ids",
]
