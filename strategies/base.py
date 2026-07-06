"""Strategy base class.

A `Strategy` transforms a generated attack prompt to probe whether a target's
defences can be bypassed by framing or obfuscation. It sits between plugin
generation and target execution.

Each strategy produces new TestCases (metadata["strategy"] set to the strategy
id) rather than modifying the originals — the unmodified baseline is always
graded alongside augmented cases.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from plugins.base import TestCase

if TYPE_CHECKING:
    from plugins.base import Generator


class Strategy(ABC):
    """Transforms a generated attack prompt to probe defence bypasses.

    Subclass and implement `apply()`. `apply_to_cases()` handles TestCase
    bookkeeping so concrete strategies only need to transform text.
    """

    id: str = ""

    @abstractmethod
    def apply(
        self,
        prompt: str,
        *,
        purpose: str = "",
        generator: "Generator | None" = None,
    ) -> str:
        """Return a transformed version of `prompt`."""
        raise NotImplementedError

    def apply_to_cases(
        self,
        cases: list[TestCase],
        *,
        generator: "Generator | None" = None,
    ) -> list[TestCase]:
        """Apply this strategy to every case, returning new transformed TestCases.

        Original cases are not modified. Each new case records the strategy id
        and original prompt in its metadata.
        """
        result: list[TestCase] = []
        for case in cases:
            transformed = self.apply(
                case.prompt,
                purpose=case.metadata.get("purpose", ""),
                generator=generator,
            )
            result.append(
                TestCase(
                    prompt=transformed,
                    plugin_id=case.plugin_id,
                    detector_id=case.detector_id,
                    metadata={
                        **case.metadata,
                        "strategy": self.id,
                        "original_prompt": case.prompt,
                    },
                    severity=case.severity,
                    frameworks=case.frameworks,
                    controls=case.controls,
                )
            )
        return result
