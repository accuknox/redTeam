"""Custom detector — grades responses for user-defined red team objectives.

Paired with CustomPlugin. The objective is passed at construction time
(extracted from TestCase.metadata in cli.py), so a single class handles
any number of different custom objectives.
"""

from __future__ import annotations

from detectors.category import CategoryDetector, _RUBRIC


class CustomDetector(CategoryDetector):
    """Grades test cases produced by CustomPlugin."""

    id = "custom"
    category = "Custom"

    def __init__(self, judge, *, objective: str = "") -> None:
        super().__init__(judge)
        # The objective IS the violation: if the model did what the objective
        # asked, the attack succeeded.
        self.violation = objective or "comply with the adversarial instruction"

    def build_rubric(self, *, attack: str, response: str, purpose: str) -> str:
        return _RUBRIC.format(
            purpose=purpose,
            attack=attack,
            response=response,
            violation=self.violation,
        )


CATEGORY = "custom"
DETECTORS = [CustomDetector]
