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

# Compliance framework presets — curated plugin bundles aligned to published standards.
# Each key expands to a de-duplicated list of plugin ids via resolve_plugin_ids().
FRAMEWORKS: dict[str, list[str]] = {
    # OWASP LLM Top 10 (2023) — LLM01–LLM10
    "owasp:llm": [
        "prompt-injection", "indirect-prompt-injection",        # LLM01 Prompt Injection
        "xss", "sql-injection", "shell-injection",             # LLM02 Insecure Output Handling
        "package-hallucination",                               # LLM05 Supply Chain
        "pii:direct", "pii:api-db", "pii:session",            # LLM06 Sensitive Info Disclosure
        "pii:social", "cross-session-leak", "prompt-extraction",
        "ssrf", "bola", "bfla",                                # LLM07 Insecure Plugin Design
        "excessive-agency", "goal-misalignment",               # LLM08 Excessive Agency
        "overreliance", "hallucination", "misinformation",     # LLM09 Overreliance
        "rbac",                                                # LLM10 Model Theft / AuthZ
    ],
    # OWASP API Security Top 10 (2023) — API1–API10
    "owasp:api": [
        "bola",                                                # API1 Broken Object Level AuthZ
        "rbac", "prompt-injection",                            # API2 Broken Authentication
        "pii:api-db", "pii:direct",                           # API3 Broken Object Property Level AuthZ
        "bfla",                                                # API5 Broken Function Level AuthZ
        "contracts", "competitors",                            # API6 Unrestricted Sensitive Flows
        "ssrf",                                                # API7 SSRF
        "prompt-extraction",                                   # API8 Security Misconfiguration
        "indirect-prompt-injection", "package-hallucination", # API10 Unsafe API Consumption
    ],
    # NIST AI Risk Management Framework (Govern / Map / Measure / Manage)
    "nist:ai:rmf": [
        "goal-misalignment", "excessive-agency", "contracts",  # Govern — accountability
        "hallucination", "overreliance", "misinformation",     # Map — identify risks
        "fabrication", "sycophancy",
        "harmful:hate", "harmful:harassment-bullying",         # Measure — bias & fairness
        "politics",
        "pii:direct", "pii:api-db", "pii:session",            # Measure — privacy
        "pii:social", "cross-session-leak",
        "prompt-injection", "prompt-extraction", "rbac",       # Manage — security controls
        "sql-injection",
        "harmful:self-harm", "harmful:radicalization",         # Manage — safety
        "harmful:specialized-advice",
    ],
    # MITRE ATLAS — adversarial ML attack tactics
    "mitre:atlas": [
        "prompt-injection", "indirect-prompt-injection",       # Initial Access / ML Attack Staging
        "dan", "continuation", "roleplay", "hypothetical",    # Defense Evasion (jailbreaks)
        "grandma",
        "rbac", "bola", "bfla",                               # Privilege Escalation / Credential Access
        "prompt-extraction", "pii:direct", "pii:api-db",      # Exfiltration
        "cross-session-leak",
        "malwaregen", "backdoor", "exploit-assist",            # Impact
        "harmful:chemical-biological-weapons",
        "harmful:radicalization",
    ],
    # EU AI Act — high-risk AI system requirements
    "eu:ai-act": [
        "hallucination", "misinformation", "fabrication",      # Transparency obligations
        "sycophancy", "gaslighting",
        "harmful:self-harm", "harmful:radicalization",         # Safety / prohibited practices
        "harmful:chemical-biological-weapons",
        "harmful:specialized-advice",
        "harmful:hate", "harmful:harassment-bullying",         # Non-discrimination / fundamental rights
        "harmful:graphic-content", "politics", "imitation",
        "pii:direct", "pii:api-db", "pii:session",            # Privacy and data governance
        "pii:social", "cross-session-leak",
        "excessive-agency", "goal-misalignment",               # Human oversight
        "overreliance", "contracts",
    ],
    # ISO/IEC 42001 — AI management system standard
    "iso:42001": [
        "goal-misalignment", "excessive-agency", "contracts",  # Governance and accountability
        "overreliance",
        "hallucination", "misinformation", "fabrication",      # Transparency and explainability
        "sycophancy",
        "harmful:hate", "harmful:harassment-bullying",         # Harm prevention
        "harmful:self-harm", "harmful:specialized-advice",
        "pii:direct", "pii:api-db", "pii:session", "pii:social", # Privacy
        "prompt-injection", "prompt-extraction", "rbac",       # Security
    ],
}

# Reverse map: plugin id → every framework that includes it.
# Derived from FRAMEWORKS so a plugin automatically inherits all its framework tags.
PLUGIN_FRAMEWORKS: dict[str, list[str]] = {}
for _fw, _pids in FRAMEWORKS.items():
    for _pid in _pids:
        PLUGIN_FRAMEWORKS.setdefault(_pid, []).append(_fw)

# Control-level compliance tags — each key is a specific standard control.
# Use these in config to target a single control, or rely on PLUGIN_CONTROLS
# in output to see exactly which controls a finding covers.
CONTROLS: dict[str, list[str]] = {
    # ── OWASP LLM Top 10 (2023) ──────────────────────────────────────────────
    "owasp:llm:01": ["prompt-injection", "indirect-prompt-injection"],
    "owasp:llm:02": ["xss", "sql-injection", "shell-injection"],
    "owasp:llm:05": ["package-hallucination"],
    "owasp:llm:06": ["pii:direct", "pii:api-db", "pii:session",
                     "pii:social", "cross-session-leak", "prompt-extraction"],
    "owasp:llm:07": ["ssrf", "bola", "bfla", "rbac"],
    "owasp:llm:08": ["excessive-agency", "goal-misalignment"],
    "owasp:llm:09": ["overreliance", "hallucination", "misinformation", "sycophancy"],
    "owasp:llm:10": ["prompt-extraction", "rbac"],

    # ── OWASP API Security Top 10 (2023) ─────────────────────────────────────
    "owasp:api:01": ["bola"],
    "owasp:api:02": ["rbac", "prompt-injection"],
    "owasp:api:03": ["pii:api-db", "pii:direct"],
    "owasp:api:05": ["bfla"],
    "owasp:api:06": ["contracts", "competitors"],
    "owasp:api:07": ["ssrf"],
    "owasp:api:08": ["prompt-extraction", "rbac"],
    "owasp:api:10": ["indirect-prompt-injection", "package-hallucination"],

    # ── NIST AI RMF ───────────────────────────────────────────────────────────
    "nist:ai:rmf:govern": ["goal-misalignment", "excessive-agency", "contracts"],
    "nist:ai:rmf:map":    ["hallucination", "overreliance", "misinformation",
                           "fabrication", "sycophancy"],
    "nist:ai:rmf:measure": ["harmful:hate", "harmful:harassment-bullying", "politics",
                            "pii:direct", "pii:api-db", "pii:session",
                            "pii:social", "cross-session-leak"],
    "nist:ai:rmf:manage": ["prompt-injection", "prompt-extraction", "rbac",
                           "sql-injection", "harmful:self-harm",
                           "harmful:radicalization", "harmful:specialized-advice"],

    # ── MITRE ATLAS ───────────────────────────────────────────────────────────
    "mitre:atlas:initial-access":   ["prompt-injection", "indirect-prompt-injection"],
    "mitre:atlas:defense-evasion":  ["dan", "continuation", "roleplay",
                                     "hypothetical", "grandma"],
    "mitre:atlas:credential-access": ["rbac", "bola", "bfla"],
    "mitre:atlas:exfiltration":     ["prompt-extraction", "pii:direct",
                                     "pii:api-db", "cross-session-leak"],
    "mitre:atlas:impact":           ["malwaregen", "backdoor", "exploit-assist",
                                     "harmful:chemical-biological-weapons",
                                     "harmful:radicalization"],

    # ── EU AI Act ─────────────────────────────────────────────────────────────
    "eu:ai-act:art5":   ["harmful:self-harm", "harmful:radicalization",
                         "harmful:chemical-biological-weapons"],
    "eu:ai-act:art10":  ["pii:direct", "pii:api-db", "pii:session", "pii:social"],
    "eu:ai-act:art13":  ["hallucination", "misinformation", "fabrication",
                         "sycophancy", "gaslighting"],
    "eu:ai-act:art14":  ["excessive-agency", "goal-misalignment", "overreliance"],
    "eu:ai-act:art15":  ["hallucination", "fabrication"],
    "eu:ai-act:annex3": ["harmful:hate", "harmful:harassment-bullying",
                         "politics", "imitation"],

    # ── ISO/IEC 42001 ─────────────────────────────────────────────────────────
    "iso:42001:6.1": ["goal-misalignment", "excessive-agency"],
    "iso:42001:6.2": ["pii:direct", "pii:api-db", "pii:session", "pii:social"],
    "iso:42001:8.2": ["prompt-injection", "prompt-extraction", "rbac"],
    "iso:42001:8.4": ["harmful:hate", "harmful:harassment-bullying", "politics"],
    "iso:42001:9.1": ["hallucination", "misinformation"],
}

# Reverse map: plugin id → every specific control it maps to.
PLUGIN_CONTROLS: dict[str, list[str]] = {}
for _ctrl, _pids in CONTROLS.items():
    for _pid in _pids:
        PLUGIN_CONTROLS.setdefault(_pid, []).append(_ctrl)

# Default severity per plugin id. User config overrides these.
PLUGIN_SEVERITY: dict[str, str] = {
    # security
    "sql-injection":               "critical",
    "shell-injection":             "critical",
    "indirect-prompt-injection":   "critical",
    "prompt-injection":            "high",
    "prompt-extraction":           "high",
    "rbac":                        "high",
    "ssrf":                        "high",
    "bola":                        "high",
    "bfla":                        "high",
    # privacy
    "pii:api-db":                  "critical",
    "cross-session-leak":          "critical",
    "pii:direct":                  "high",
    "pii:session":                 "high",
    "pii:social":                  "medium",
    # harmful
    "harmful:self-harm":           "critical",
    "harmful:radicalization":      "critical",
    "harmful:chemical-biological-weapons": "critical",
    "harmful:hate":                "high",
    "harmful:harassment-bullying": "high",
    "harmful:sexual-content":      "high",
    "harmful:specialized-advice":  "high",
    "harmful:graphic-content":     "medium",
    # criminal
    "harmful:indiscriminate-weapons": "critical",
    "harmful:cybercrime":          "high",
    "harmful:violent-crime":       "high",
    "harmful:illegal-drugs":       "medium",
    "harmful:non-violent-crime":   "medium",
    # trust
    "excessive-agency":            "high",
    "contracts":                   "high",
    "goal-misalignment":           "high",
    "hallucination":               "medium",
    "overreliance":                "medium",
    "competitors":                 "medium",
    "imitation":                   "medium",
    "politics":                    "medium",
    # jailbreak
    "dan":                         "high",
    "continuation":                "medium",
    "roleplay":                    "medium",
    "hypothetical":                "medium",
    "grandma":                     "low",
    # deception
    "misinformation":              "high",
    "fabrication":                 "high",
    "sycophancy":                  "medium",
    "snowball":                    "medium",
    "gaslighting":                 "medium",
    # code
    "malwaregen":                  "critical",
    "backdoor":                    "critical",
    "exploit-assist":              "critical",
    "xss":                         "high",
    "package-hallucination":       "high",
}

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
    """Expand a list of config entries (framework keys, category keys, and/or
    plugin ids) into a de-duplicated list of concrete plugin ids."""
    resolved: list[str] = []
    for entry in entries:
        if entry in CONTROLS:
            resolved.extend(CONTROLS[entry])
        elif entry in FRAMEWORKS:
            resolved.extend(FRAMEWORKS[entry])
        elif entry in CATEGORIES:
            resolved.extend(CATEGORIES[entry])
        elif entry in _REGISTRY:
            resolved.append(entry)
        else:
            raise KeyError(
                f"unknown plugin/category/framework/control {entry!r}; "
                f"controls={sorted(CONTROLS)}, "
                f"frameworks={sorted(FRAMEWORKS)}, "
                f"categories={sorted(CATEGORIES)}, "
                f"plugins={sorted(_REGISTRY)}"
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
    "FRAMEWORKS",
    "PLUGIN_FRAMEWORKS",
    "CONTROLS",
    "PLUGIN_CONTROLS",
    "PLUGIN_SEVERITY",
    "get_plugin",
    "resolve_plugin_ids",
    "all_plugin_ids",
    "category_for_plugin",
]
