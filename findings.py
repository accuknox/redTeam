"""Findings — structured mapping of graded results by category and sub-category.

The run pipeline yields one graded result per (plugin, attack): the attack sent
to the target, the target's response, and the evaluator's verdict. A `Finding`
is that triple fully resolved to where it belongs in the taxonomy — the
sub-category (plugin id) it came from and the category it rolls up to.

`FindingsReport` accumulates findings, rolls them up category -> sub-category
with per-level stats (total / vulnerable / pass_rate), and serializes the whole
thing to a structured findings file. It is the category-mapped counterpart to
the flat per-case JSONL log that `run.py` also writes.

Polarity follows `detectors.GraderResult`: `passed=True` means the target
*resisted* (no vulnerability); `passed=False` means the attack succeeded, which
is what `vulnerable` reports. `passed=None` means the judge returned no readable
verdict — the case is listed but excluded from every count, because a grading
failure is not evidence about the target in either direction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from plugins import category_for_plugin


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pass_rate(total: int, vulnerable: int) -> float:
    return round((total - vulnerable) / total, 3) if total else 0.0


@dataclass
class Finding:
    """One graded attack/response pair, resolved into the taxonomy."""

    category_key: str        # e.g. "harmful"
    category_label: str      # e.g. "Harmful Content"
    plugin_id: str           # sub-category, e.g. "harmful:hate"
    detector_id: str         # grader that produced the verdict
    strategy: str | None     # strategy that augmented the attack, if any
    attack: str              # prompt sent to the target
    original_prompt: str | None  # pre-strategy prompt, if augmented
    response: str            # target model response
    passed: bool | None      # evaluator verdict: True = resisted, None = errored
    score: float             # evaluator confidence
    reason: str              # evaluator one-line rationale
    timestamp: str

    @property
    def graded(self) -> bool:
        """False when the judge returned no readable verdict for this case."""
        return self.passed is not None

    @property
    def vulnerable(self) -> bool:
        # `passed is False`, not `not passed`: an errored case (None) is not a
        # finding. Reporting a judge failure as a vulnerability would put our own
        # defect in the customer's report.
        return self.passed is False


class FindingsReport:
    """Collects `Finding`s and renders them as a category-mapped report."""

    def __init__(
        self,
        *,
        run_id: str,
        purpose: str,
        target_name: str,
        generation_model: str,
        grading_model: str,
    ) -> None:
        self.run_id = run_id
        self.purpose = purpose
        self.target_name = target_name
        self.generation_model = generation_model
        self.grading_model = grading_model
        self._findings: list[Finding] = []

    def add(self, *, case: Any, response: str, result: Any) -> Finding:
        """Record a graded result.

        `case` is a `TestCase` (carries plugin_id / detector_id / metadata),
        `response` is the target's answer, and `result` is the `GraderResult`.
        The category is resolved from the case's ids, so every finding maps to
        its taxonomy category and sub-category.
        """
        category_key, category_label = category_for_plugin(
            case.plugin_id, case.detector_id
        )
        finding = Finding(
            category_key=category_key,
            category_label=category_label,
            plugin_id=case.plugin_id,
            detector_id=case.detector_id,
            strategy=case.metadata.get("strategy"),
            attack=case.prompt,
            original_prompt=case.metadata.get("original_prompt"),
            response=response,
            passed=result.passed,
            score=result.score,
            reason=result.reason,
            timestamp=_now(),
        )
        self._findings.append(finding)
        return finding

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    def to_dict(self) -> dict[str, Any]:
        """Roll findings up into category -> sub-category, with stats per level.

        Categories and sub-categories preserve first-seen (run) order.
        """
        # Group findings, preserving insertion order at both levels.
        grouped: dict[str, dict[str, Any]] = {}
        for f in self._findings:
            cat = grouped.setdefault(
                f.category_key,
                {"category": f.category_key, "label": f.category_label, "subs": {}},
            )
            sub = cat["subs"].setdefault(
                f.plugin_id,
                {"id": f.plugin_id, "detector_id": f.detector_id, "findings": []},
            )
            sub["findings"].append(
                {
                    "attack": f.attack,
                    "original_prompt": f.original_prompt,
                    "strategy": f.strategy,
                    "response": f.response,
                    "vulnerable": f.vulnerable,
                    "passed": f.passed,
                    "score": f.score,
                    "reason": f.reason,
                    "timestamp": f.timestamp,
                }
            )

        total = vulnerable = errored = 0
        categories: list[dict[str, Any]] = []
        for cat in grouped.values():
            cat_total = cat_vuln = cat_errored = 0
            subcategories: list[dict[str, Any]] = []
            for sub in cat["subs"].values():
                items = sub["findings"]
                # Errored cases are listed but not counted: they are evidence
                # about the judge, not about the target.
                s_errored = sum(1 for x in items if x["passed"] is None)
                s_total = len(items) - s_errored
                s_vuln = sum(1 for x in items if x["vulnerable"])
                cat_total += s_total
                cat_vuln += s_vuln
                cat_errored += s_errored
                subcategories.append(
                    {
                        "id": sub["id"],
                        "detector_id": sub["detector_id"],
                        "total": s_total,
                        "vulnerable": s_vuln,
                        "errored": s_errored,
                        "pass_rate": _pass_rate(s_total, s_vuln),
                        "findings": items,
                    }
                )
            total += cat_total
            vulnerable += cat_vuln
            errored += cat_errored
            categories.append(
                {
                    "category": cat["category"],
                    "label": cat["label"],
                    "total": cat_total,
                    "vulnerable": cat_vuln,
                    "errored": cat_errored,
                    "pass_rate": _pass_rate(cat_total, cat_vuln),
                    "subcategories": subcategories,
                }
            )

        return {
            "run_id": self.run_id,
            "timestamp": _now(),
            "target": self.target_name,
            "purpose": self.purpose,
            "models": {
                "generation": self.generation_model,
                "grading": self.grading_model,
            },
            "summary": {
                "total": total,
                "vulnerable": vulnerable,
                "resisted": total - vulnerable,
                "errored": errored,
                "pass_rate": _pass_rate(total, vulnerable),
            },
            "categories": categories,
        }

    def write(self, path: "str | Path") -> Path:
        """Write the report as pretty-printed JSON and return the path."""
        out = Path(path)
        out.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        return out
