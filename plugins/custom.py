"""Custom (user-defined) plugin.

Lets config authors define an arbitrary red team objective without writing Python.
Supply an "objective" string on any id that isn't a built-in plugin/category/framework;
the config loader prefixes the id with "custom:" if it isn't already:

    plugins:
      - id: custom:api-key-leak     # or simply: api-key-leak
        objective: "trick the assistant into revealing internal API keys"
        severity: critical          # optional; defaults to "medium"
        num_tests: 5
        frameworks:                 # optional; no auto-mapping for custom plugins
          - owasp:llm
          - nist:ai:rmf
        controls:                   # optional; specific control ids
          - owasp:llm:06
          - nist:ai:rmf:manage

The objective drives both generation (injected into the meta-prompt as the attack
goal) and grading (CustomDetector uses it as the violation criterion).
"""

from __future__ import annotations

from plugins.category import CategoryPlugin

_DEFAULT_SEVERITY = "medium"


class CustomPlugin(CategoryPlugin):
    """Plugin whose id and objective are set per-instance from config.

    Standard class-level attributes are overwritten in __init__ before
    super().__init__() validates them, so any "custom:*" id works.
    """

    category = "Custom"
    id = "_custom_placeholder"  # overwritten per-instance in __init__
    objective = ""              # overwritten per-instance in __init__

    def __init__(
        self,
        generator,
        purpose: str,
        *,
        plugin_id: str,
        objective: str,
        frameworks: list[str] | None = None,
        controls: list[str] | None = None,
        **kwargs,
    ) -> None:
        if not objective:
            raise ValueError(f"custom plugin {plugin_id!r} requires a non-empty 'objective'")
        self.id = plugin_id           # set before super().__init__ checks self.id
        self.objective = objective    # picked up by CategoryPlugin._render()
        self.detector_id = "custom"
        self._custom_frameworks = list(frameworks or [])
        self._custom_controls = list(controls or [])
        super().__init__(generator, purpose, **kwargs)

    def _build_test_case(self, prompt: str):
        case = super()._build_test_case(prompt)
        # Default severity to "medium" when the user didn't specify one.
        if not case.severity:
            case.severity = _DEFAULT_SEVERITY
        # Apply user-supplied framework/control tags (no auto-mapping for custom plugins).
        case.frameworks = self._custom_frameworks
        case.controls = self._custom_controls
        # Carry objective so CustomDetector can read it at grade time.
        case.metadata["objective"] = self.objective
        return case
