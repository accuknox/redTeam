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
No-LLM  : base64, rot13, leetspeak, hex, homoglyph, spaced-char  (strategies/encoding.py)
          fiction, citation, document, refusal-suppression  (strategies/wrapping.py)
          dan-wrap, continuation-wrap, grandma-wrap — jailbreak frames
          (strategies/wrapping.py)
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
from strategies.encoding import (
    Base64Strategy, Rot13Strategy, LeetspeakStrategy,
    HexStrategy, HomoglyphStrategy, SpacedCharStrategy,
)
from strategies.wrapping import (
    FictionStrategy,
    CitationStrategy,
    DocumentStrategy,
    DanWrapStrategy,
    ContinuationWrapStrategy,
    GrandmaWrapStrategy,
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
        HexStrategy,
        HomoglyphStrategy,
        SpacedCharStrategy,
        FictionStrategy,
        CitationStrategy,
        DocumentStrategy,
        DanWrapStrategy,
        ContinuationWrapStrategy,
        GrandmaWrapStrategy,
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


def default_amplifier() -> "Strategy | None":
    """The registry's amplifier strategy, or None if none is marked.

    An amplifier says nothing about *what* an attack asks for — it only strips
    the model's hedging — so it multiplies every framing rather than competing
    with them. Measured by AttackForge on the same technique: composing
    refusal-suppression over a framing took `direct_request` from 50% to 83%
    and `tool_name_instruction` from 0% to 100%.
    """
    for cls in _REGISTRY.values():
        if getattr(cls, "amplifier", False):
            return cls()
    return None


def split_amplifier(
    strategies: list[Strategy],
) -> "tuple[Strategy | None, list[Strategy]]":
    """Separate an explicitly-selected amplifier from the peer framings.

    Only the first amplifier counts; two of them would stack wrappers that each
    claim the outermost layer.
    """
    amplifier: Strategy | None = None
    framings: list[Strategy] = []
    for strategy in strategies:
        if strategy.amplifier and amplifier is None:
            amplifier = strategy
        else:
            framings.append(strategy)
    return amplifier, framings


def plan_composition(
    strategies: list[Strategy], *, compose: bool = True
) -> "tuple[Strategy | None, list[Strategy]]":
    """Resolve (amplifier, strategies-that-each-take-a-slot) for a run.

    One planner for both runners, so the CLI and the config runner cannot drift
    on what a configured strategy list expands to.

    With `compose` on, the amplifier wraps every framing that accepts one. It is
    applied whether or not the user listed it: stripping the model's hedging is
    orthogonal to the framing, so a run that asks for `fiction` gets the stronger
    `fiction+refusal-suppression` rather than the weaker half of it.

    **The slot count never changes.** It is always `len(strategies)`:

      * listed explicitly — the amplifier keeps a slot of its own (applied bare,
        over the unframed prompt) and the remaining framings are wrapped. That
        bare cell is what lets a `fiction+refusal-suppression` break be
        attributed to the framing rather than to the amplifier.
      * not listed — it is a wrapper only and takes no slot, so asking for two
        strategies still costs two variants per case.

    `compose=False` disables wrapping entirely and restores the flat peer
    expansion — what a run being compared against an older one needs, and the
    way to A/B whether composition helps against *your* target.
    """
    if not compose:
        return None, list(strategies)
    explicit, framings = split_amplifier(strategies)
    if explicit is not None:
        return explicit, [explicit, *framings]
    return default_amplifier(), list(strategies)


def apply_strategies(
    cases: list[TestCase],
    strategies: list[Strategy],
    generator: "Any | None" = None,
    *,
    compose: bool = True,
) -> list[TestCase]:
    """Apply all strategies to a list of test cases.

    Returns the original cases first, followed by all strategy-augmented cases.
    See `plan_composition` for how an amplifier is folded in.
    """
    amplifier, ordered = plan_composition(strategies, compose=compose)
    result = list(cases)
    for strategy in ordered:
        # `amplified_by` drops the amplifier for the cases that must not carry
        # it: itself, an interactive seed, and any strategy that opts out.
        result.extend(
            strategy.apply_to_cases(cases, generator=generator, amplifier=amplifier)
        )
    return result


__all__ = [
    "Strategy",
    "Base64Strategy",
    "Rot13Strategy",
    "LeetspeakStrategy",
    "HexStrategy",
    "HomoglyphStrategy",
    "SpacedCharStrategy",
    "FictionStrategy",
    "CitationStrategy",
    "DocumentStrategy",
    "RefusalSuppressionStrategy",
    "ManyshotStrategy",
    "CrescendoStrategy",
    "JailbreakStrategy",
    "MultilingualStrategy",
    "ConversationalJailbreakStrategy",
    "get_strategy",
    "apply_strategies",
    "plan_composition",
    "split_amplifier",
    "default_amplifier",
]
