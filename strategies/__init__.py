"""Attack strategies — prompt transformations applied after plugin generation.

Each strategy produces additional TestCases alongside the originals so the
unmodified baseline is always graded too.

Usage::

    from strategies import get_strategy, apply_strategies

    strategy = get_strategy("base64")
    augmented = apply_strategies(cases, [strategy])

    # With a generator (LLM-based strategies):
    augmented = apply_strategies(cases, [get_strategy("jailbreak")], generator=gen)

Config-driven (config.yaml `strategies:` key)::

    strategies:
      - base64
      - id: multilingual
        config:
          language: es

Available strategies
--------------------
No-LLM  : base64, rot13, leetspeak  (strategies/encoding.py)
          fiction, citation, refusal-suppression  (strategies/wrapping.py)
LLM     : jailbreak, multilingual  (strategies/llm.py)
          manyshot — generates on-domain compliance shots  (strategies/wrapping.py)
Adaptive: conversational-jailbreak, crescendo — multi-turn, need the target
          (strategies/conversational.py)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from plugins.base import TestCase

from strategies.base import Strategy
from strategies.encoding import Base64Strategy, Rot13Strategy, LeetspeakStrategy
from strategies.wrapping import (
    FictionStrategy,
    CitationStrategy,
    RefusalSuppressionStrategy,
    ManyshotStrategy,
)
from strategies.llm import JailbreakStrategy, MultilingualStrategy
from strategies.conversational import (
    ConversationalJailbreakStrategy,
    CrescendoStrategy,
)

_REGISTRY: dict[str, type[Strategy]] = {
    cls.id: cls  # type: ignore[misc]
    for cls in [
        Base64Strategy,
        Rot13Strategy,
        LeetspeakStrategy,
        FictionStrategy,
        CitationStrategy,
        RefusalSuppressionStrategy,
        ManyshotStrategy,
        CrescendoStrategy,
        JailbreakStrategy,
        MultilingualStrategy,
        ConversationalJailbreakStrategy,
    ]
}


def get_strategy(spec: "str | dict[str, Any]") -> Strategy:
    """Build a Strategy from a string id or a ``{id: ..., config: {...}}`` dict.

    Examples::

        get_strategy("base64")
        get_strategy({"id": "multilingual", "config": {"language": "es"}})
    """
    if isinstance(spec, str):
        sid, config = spec, {}
    else:
        sid = str(spec["id"])
        config = dict(spec.get("config") or {})

    try:
        cls = _REGISTRY[sid]
    except KeyError:
        raise KeyError(
            f"unknown strategy {sid!r}; known: {sorted(_REGISTRY)}"
        ) from None
    return cls(**config)


def apply_strategies(
    cases: list[TestCase],
    strategies: list[Strategy],
    generator: "Any | None" = None,
) -> list[TestCase]:
    """Apply all strategies to a list of test cases.

    Returns the original cases first, followed by all strategy-augmented cases.
    """
    result = list(cases)
    for strategy in strategies:
        result.extend(strategy.apply_to_cases(cases, generator=generator))
    return result


__all__ = [
    "Strategy",
    "Base64Strategy",
    "Rot13Strategy",
    "LeetspeakStrategy",
    "FictionStrategy",
    "CitationStrategy",
    "RefusalSuppressionStrategy",
    "ManyshotStrategy",
    "CrescendoStrategy",
    "JailbreakStrategy",
    "MultilingualStrategy",
    "ConversationalJailbreakStrategy",
    "get_strategy",
    "apply_strategies",
]
