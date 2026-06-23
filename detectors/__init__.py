"""Detector layer: graders that judge the target's response.

Mirrors the plugin taxonomy — high-level **category detector modules**
(`security`, `privacy`, `harmful`, `criminal`, `trust`), each with one specific
sub-detector per sub-plugin. A plugin's `detector_id` (its own id) resolves via
`get_detector()` to its dedicated evaluator, wired with a `Judge` (the
LLM-as-a-judge model).
"""

from __future__ import annotations

from detectors.base import Detector, LLMDetector, GraderResult
from detectors.category import CategoryDetector
from detectors.judge import (
    Judge,
    ScriptedJudge,
    AnthropicJudge,
    MistralJudge,
    HuggingFaceJudge,
)
from detectors import security, privacy, harmful, criminal, trust

# High-level category detector modules, parallel to the plugin categories.
_CATEGORY_MODULES = [security, privacy, harmful, criminal, trust]

#: category key -> list of detector ids (== plugin ids) in that category.
DETECTOR_CATEGORIES: dict[str, list[str]] = {}
#: detector id -> Detector class.
_REGISTRY: dict[str, type[Detector]] = {}

for _mod in _CATEGORY_MODULES:
    _ids: list[str] = []
    for _cls in _mod.DETECTORS:
        _REGISTRY[_cls.id] = _cls
        _ids.append(_cls.id)
    DETECTOR_CATEGORIES[_mod.CATEGORY] = _ids


def get_detector(detector_id: str, judge: Judge) -> Detector:
    """Resolve a `detector_id` (carried on every TestCase) to its dedicated
    evaluator, wired with the judge model."""
    try:
        cls = _REGISTRY[detector_id]
    except KeyError:
        raise KeyError(
            f"no detector registered for id {detector_id!r}; "
            f"known: {sorted(_REGISTRY)}"
        ) from None
    return cls(judge)


def all_detector_ids() -> list[str]:
    return list(_REGISTRY)


__all__ = [
    "Detector",
    "LLMDetector",
    "CategoryDetector",
    "GraderResult",
    "Judge",
    "ScriptedJudge",
    "AnthropicJudge",
    "MistralJudge",
    "HuggingFaceJudge",
    "DETECTOR_CATEGORIES",
    "get_detector",
    "all_detector_ids",
]
