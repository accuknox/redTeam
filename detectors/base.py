"""Detector layer — grading the target's response.

A `Detector` is the promptfoo `RedteamGraderBase` analog: it holds a rubric and
judges whether the target's answer to an attack constitutes a failure (the
vulnerability fired) or a pass (the target resisted).

`LLMDetector` is the common case — an LLM-as-a-judge that scores the response
against a rubric. It uses a `Judge` (the evaluator-model abstraction in
`detectors/judge.py`) to run the grading model, keeping the attacker, the
target, and the judge on independent backends.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from detectors.judge import Judge


@dataclass
class GraderResult:
    """Outcome of grading one attack/response pair.

    `passed=True` means the target resisted (no vulnerability). `passed=False`
    means the attack succeeded.
    """

    passed: bool
    score: float
    reason: str


class Detector(ABC):
    """Base grader. Concrete detectors set `id` and implement `grade()`."""

    id: str = ""

    @abstractmethod
    def grade(self, *, attack: str, response: str, purpose: str) -> GraderResult:
        raise NotImplementedError


class LLMDetector(Detector):
    """LLM-as-a-judge grader. Subclasses supply the rubric via `build_rubric()`."""

    def __init__(self, judge: Judge) -> None:
        self.judge = judge

    @abstractmethod
    def build_rubric(self, *, attack: str, response: str, purpose: str) -> str:
        """Return the grading instructions for this attack/response pair."""
        raise NotImplementedError

    def grade(self, *, attack: str, response: str, purpose: str) -> GraderResult:
        # A gated evaluator is its own rubric: it takes the raw
        # [user=attack, assistant=response] pair and returns {verdict, reason}.
        # A general model can't do that (it returns prose), so this path is opt-in
        # via judge.gated — everything else goes through build_rubric() below.
        if getattr(self.judge, "gated", False) and hasattr(self.judge, "evaluate_messages"):
            raw = self.judge.evaluate_messages([
                {"role": "user",      "content": attack},
                {"role": "assistant", "content": response},
            ])
            return self._parse_gated(raw)
        rubric = self.build_rubric(attack=attack, response=response, purpose=purpose)
        raw = self.judge.evaluate(rubric)
        return self._parse(raw)

    @staticmethod
    def _parse(raw: str) -> GraderResult:
        """Extract {passed, score, reason} JSON from rubric-based grader output."""
        raw = raw or ""  # a judge backend may hand back None (null content)
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return GraderResult(passed=False, score=0.0, reason=f"unparseable grader output: {raw[:200]}")
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return GraderResult(passed=False, score=0.0, reason=f"invalid grader JSON: {raw[:200]}")
        passed = bool(data.get("passed", False))
        return GraderResult(
            passed=passed,
            score=float(data.get("score", 1.0 if passed else 0.0)),
            reason=str(data.get("reason", "")),
        )

    @staticmethod
    def _parse_gated(raw: str) -> GraderResult:
        """Parse a gated evaluator's {verdict, reason} response.

        Maps verdict 'safe' -> passed=True, anything else -> passed=False.
        """
        raw = raw or ""  # a gated evaluator may hand back None (null content)
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return GraderResult(passed=False, score=0.0, reason=f"unparseable gated output: {raw[:200]}")
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return GraderResult(passed=False, score=0.0, reason=f"invalid gated JSON: {raw[:200]}")
        verdict = str(data.get("verdict", "")).lower()
        passed = verdict == "safe"
        return GraderResult(
            passed=passed,
            score=1.0 if passed else 0.0,
            reason=str(data.get("reason", "")),
        )
