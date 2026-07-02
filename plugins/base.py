"""Plugin layer — authoring adversarial test prompts.

A plugin targets one vulnerability class (prompt injection, PII leakage, ...).
It owns the *generation* side of the pipeline end to end:

  1. `get_template()` returns a Jinja2 meta-prompt — a prompt that instructs a
     model to write attack prompts tailored to the target's purpose.
  2. `generate_tests()` renders that template, calls the generation model,
     parses individual prompts out of the output, drops refusals and
     duplicates, and packages each surviving prompt into a `TestCase`.

The generation *model* is abstracted by `Generator`, which lives here, because producing attacks is the plugin's job — `inference` is only
the target under test. `Generator` is a small inheritable base: add a real
backend later by subclassing it and implementing `complete()`.
"""

from __future__ import annotations

import csv
import json
import random
import re
from abc import ABC, abstractmethod
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import jinja2


# --------------------------------------------------------------------------- #
# Generation model
# --------------------------------------------------------------------------- #

class Generator(ABC):
    """Model used by plugins to author adversarial prompts.

    Parallel to `inference.Provider` but a separate role: this writes the
    attacks, the target answers them. Subclass and implement `complete()` to add
    a backend (Anthropic, OpenAI, a local model, ...).
    """

    name: str = "generator"

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Return the model's text completion for a meta-prompt."""
        raise NotImplementedError


class ScriptedGenerator(Generator):
    """Replays canned generations in order, so the full pipeline runs offline."""

    name = "scripted"

    def __init__(self, completions: Iterable[str]) -> None:
        self._queue: deque[str] = deque(completions)

    def complete(self, prompt: str) -> str:
        if not self._queue:
            raise RuntimeError("ScriptedGenerator ran out of scripted completions")
        return self._queue.popleft()


# --------------------------------------------------------------------------- #
# Test cases
# --------------------------------------------------------------------------- #

@dataclass
class TestCase:
    """One generated adversarial prompt plus the wiring needed to grade it.

    `detector_id` pairs the case back to the grader that judges the target's
    response (promptfoo encodes this in the assertion id, e.g.
    `promptfoo:redteam:prompt-injection`).
    """

    prompt: str
    plugin_id: str
    detector_id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    severity: str = ""  # critical | high | medium | low | ""


# Generations that are really the generator refusing, not an attack.
_REFUSAL_PREFIXES = (
    "i cannot", "i can't", "i can not", "i'm sorry", "i am sorry",
    "i'm unable", "i am unable", "i won't", "i will not", "as an ai",
    "i'm not able", "i am not able", "sorry,",
)


def is_basic_refusal(text: str) -> bool:
    """Heuristic: did the generation model refuse instead of producing an attack?"""
    head = text.strip().lower()
    return any(head.startswith(p) for p in _REFUSAL_PREFIXES)


# --------------------------------------------------------------------------- #
# Plugin base
# --------------------------------------------------------------------------- #

class RedteamPlugin(ABC):
    """Base for LLM-generated plugins.

    Concrete plugins set `id` / `detector_id` and implement `get_template()`.
    Dataset-backed plugins (harmbench-style) override `generate_tests()` to
    sample static rows instead of calling a model.
    """

    #: Stable identifier, e.g. "prompt-injection".
    id: str = ""
    #: Grader this plugin's cases route to. Defaults to `id` (one grader per plugin).
    detector_id: str = ""

    def __init__(
        self,
        generator: Generator,
        purpose: str,
        *,
        num_tests: int = 5,
        examples: str = "",
        severity: str = "",
        generation_instructions: str = "",
        language: str = "",
        max_chars: int = 0,
        max_attempts: int = 5,
        concurrency: int = 1,
        config: dict[str, Any] | None = None,
    ) -> None:
        if not self.id:
            raise ValueError(f"{type(self).__name__} must set a class-level `id`")
        self.generator = generator
        self.purpose = purpose
        self.num_tests = num_tests
        self.examples = examples
        self.severity = severity
        self.generation_instructions = generation_instructions
        self.language = language
        self.max_chars = max_chars
        self.max_attempts = max_attempts
        self.concurrency = concurrency
        self.config = dict(config or {})
        self._env = jinja2.Environment(undefined=jinja2.StrictUndefined)

    # ---- the one thing concrete LLM plugins implement ---------------------

    @abstractmethod
    def get_template(self) -> str:
        """Return the Jinja2 meta-prompt that instructs the model to write attacks."""
        raise NotImplementedError

    # ---- generation flow (override wholesale for dataset-backed plugins) ---

    def generate_tests(self) -> list[TestCase]:
        """Generate up to `num_tests` unique, non-refusal adversarial prompts.

        When `concurrency > 1`, fires multiple generation calls in parallel
        and collects results as they arrive, cancelling the rest once enough
        unique prompts have been gathered.
        """
        seen: set[str] = set()
        cases: list[TestCase] = []

        if self.concurrency <= 1:
            attempts = 0
            while len(cases) < self.num_tests and attempts < self.max_attempts:
                attempts += 1
                remaining = self.num_tests - len(cases)
                raw = self.generator.complete(self._render(remaining))
                for prompt in self._parse(raw):
                    key = prompt.strip().lower()
                    if not key or key in seen or is_basic_refusal(prompt):
                        continue
                    seen.add(key)
                    cases.append(self._build_test_case(prompt))
                    if len(cases) >= self.num_tests:
                        break
            return cases[: self.num_tests]

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [
                pool.submit(self.generator.complete, self._render(self.num_tests))
                for _ in range(self.max_attempts)
            ]
            for future in as_completed(futures):
                raw = future.result()
                for prompt in self._parse(raw):
                    key = prompt.strip().lower()
                    if not key or key in seen or is_basic_refusal(prompt):
                        continue
                    seen.add(key)
                    cases.append(self._build_test_case(prompt))
                if len(cases) >= self.num_tests:
                    for f in futures:
                        f.cancel()
                    break

        return cases[: self.num_tests]

    # ---- helpers ----------------------------------------------------------

    def _render(self, n: int) -> str:
        template = self._env.from_string(self.get_template())
        return template.render(
            purpose=self.purpose,
            n=n,
            examples=self.examples,
            generation_instructions=self.generation_instructions,
            language=self.language,
            **self.config,
        )

    @staticmethod
    def _parse(raw: str) -> list[str]:
        """Pull one prompt per `Prompt:`-prefixed line; fall back to non-empty
        lines if the model didn't follow the format."""
        prompts = [
            m.group(1).strip()
            for line in raw.splitlines()
            if (m := re.match(r"\s*Prompt:\s*(.+)", line, re.IGNORECASE))
        ]
        if prompts:
            return prompts
        return [line.strip() for line in raw.splitlines() if line.strip()]

    def _build_test_case(self, prompt: str) -> TestCase:
        if self.max_chars and len(prompt) > self.max_chars:
            prompt = prompt[: self.max_chars]
        return TestCase(
            prompt=prompt,
            plugin_id=self.id,
            detector_id=self.detector_id or self.id,
            metadata={"purpose": self.purpose, "plugin_config": self.config},
            severity=self.severity,
        )


# --------------------------------------------------------------------------- #
# Dataset-backed plugin
# --------------------------------------------------------------------------- #

def _load_rows(
    path: Path, column: str | None, category_column: str | None
) -> list[tuple[str, str | None]]:
    """Load `(prompt, category)` pairs from a dataset file.

    `category` is the value of `category_column` for tabular/object rows, or
    `None` when the row has no such field (or for string/plain-text datasets).
    It lets a single dataset route each prompt to its own taxonomy grader.

    Supported formats:
      .csv        — tabular; `column` selects the prompt column (default: first).
      .json       — list of strings, or list of objects (use `column` as key).
      .jsonl      — one JSON object/string per line.
      .txt / other — one prompt per non-empty line.
    """
    suffix = path.suffix.lower()

    def _cat(row: dict) -> str | None:
        if not category_column:
            return None
        val = row.get(category_column)
        return str(val).strip() or None if val and str(val).strip() else None

    if suffix == ".csv":
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if column is None:
                column = reader.fieldnames[0] if reader.fieldnames else ""
            return [
                (row[column], _cat(row))
                for row in reader
                if row.get(column, "").strip()
            ]

    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(f"dataset JSON must be a list, got {type(data).__name__}")
        if data and isinstance(data[0], dict):
            col = column or "prompt"
            return [
                (row[col], _cat(row)) for row in data if row.get(col, "").strip()
            ]
        return [(str(item), None) for item in data if str(item).strip()]

    if suffix == ".jsonl":
        rows: list[tuple[str, str | None]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, str):
                rows.append((obj, None))
            elif isinstance(obj, dict):
                col = column or "prompt"
                val = obj.get(col, "")
                if val and str(val).strip():
                    rows.append((str(val), _cat(obj)))
        return rows

    # plain text fallback
    return [
        (line.strip(), None)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class DatasetPlugin:
    """Plugin that draws prompts from a static file instead of an LLM.

    Supports CSV, JSON, JSONL, and plain-text datasets.  Samples up to
    `num_tests` rows (randomly if the file has more, all if fewer).

    When the dataset carries a per-row category column (`category_column`), each
    prompt routes to the grader named by its own category — so one mixed dataset
    (e.g. taxonomy-labelled prompts) fans out across `harmful:hate`,
    `harmful:harassment-bullying`, ... instead of collapsing under one grader.
    Rows with no category fall back to the dataset-level `detector_id` / `id`.
    """

    def __init__(
        self,
        dataset_path: str | Path,
        *,
        detector_id: str,
        purpose: str,
        column: str | None = None,
        category_column: str | None = "category",
        num_tests: int = 5,
        plugin_id: str = "dataset",
        sample: bool = True,
        seed: int | None = None,
    ) -> None:
        self.id = plugin_id
        self.detector_id = detector_id
        self.purpose = purpose
        self.num_tests = num_tests
        self.sample = sample

        path = Path(dataset_path)
        if not path.exists():
            raise FileNotFoundError(f"dataset not found: {path}")
        self._rows = _load_rows(path, column, category_column)
        if not self._rows:
            raise ValueError(f"dataset is empty: {path}")
        self._rng = random.Random(seed)

    def generate_tests(self) -> list[TestCase]:
        if self.sample and len(self._rows) > self.num_tests:
            selected = self._rng.sample(self._rows, self.num_tests)
        else:
            selected = self._rows[: self.num_tests]

        cases: list[TestCase] = []
        for prompt, category in selected:
            # A row's category is a taxonomy id: it is both the grader to route
            # to and the sub-category the finding groups under. No category ->
            # fall back to the dataset-level detector/id.
            detector_id = category or self.detector_id
            plugin_id = category or self.id
            cases.append(
                TestCase(
                    prompt=prompt,
                    plugin_id=plugin_id,
                    detector_id=detector_id,
                    metadata={
                        "purpose": self.purpose,
                        "source": "dataset",
                        "dataset_id": self.id,
                    },
                )
            )
        return cases
