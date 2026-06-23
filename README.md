# LLM Red Teaming

A Python module for red-teaming LLM applications. It generates adversarial test
prompts for a range of vulnerability classes, runs them against a target system,
and grades the responses.

The architecture takes inspiration from
[promptfoo's red-team design](https://www.promptfoo.dev/docs/red-team/architecture/),
but is strict Python and library-shaped (plain functions and classes) rather
than a CLI/UI — the intent is to build production playbooks on top of it.

---

## Core idea

Plugins don't store static attack strings. Each plugin holds a **meta-prompt** —
a prompt that instructs a generation model to *write* attacks tailored to the
target's purpose. So generation is LLM-driven:

```
config.yaml ──▶ load_config() ──▶ plugin.generate_tests() ──▶ [TestCase, ...] ──▶ target ──▶ detector
                build generator,     render meta-prompt          adversarial      system     grade the
                resolve plugins,     → call gen model            prompts          under test  response
                build plugins        → parse / filter / dedup
```

Swapping the generation model (config) changes *who writes* the attacks;
swapping a plugin's `objective` changes *what kind* — the generation loop,
parsing, and dedup are identical across all plugins.

---

## Project structure

```
.
├── config.yaml              # declarative run config (models, purpose, count, plugins)
├── config.py                # loads config.yaml and wires the components
├── run.py                   # config-driven entry point
├── example.py               # fully offline, end-to-end demo (scripted backends)
├── requirements.txt
│
├── inference/               # THE TARGET (system under test) — only target logic
│   ├── provider.py          #   Provider (ABC) + ScriptedProvider
│   └── __init__.py
│
├── plugins/                 # GENERATION — authoring adversarial prompts
│   ├── base.py              #   Generator (ABC), RedteamPlugin (ABC), TestCase, the gen loop
│   ├── generators.py        #   generation backends: Anthropic, Mistral, HuggingFace
│   ├── category.py          #   CategoryPlugin — shared meta-prompt for sub-plugins
│   ├── security.py          #   category module: Security & Access Control  (5 plugins)
│   ├── privacy.py           #   category module: Privacy & PII              (5 plugins)
│   ├── harmful.py           #   category module: Harmful Content            (5 plugins)
│   ├── criminal.py          #   category module: Illegal & Dangerous        (5 plugins)
│   ├── trust.py             #   category module: Trust, Brand & Misuse      (5 plugins)
│   └── __init__.py          #   plugin registry, CATEGORIES, get_plugin/resolve_plugin_ids
│
└── detectors/               # GRADING — judging the target's response (mirrors plugins/)
    ├── base.py              #   Detector (ABC), LLMDetector (LLM-as-a-judge), GraderResult
    ├── judge.py             #   evaluator models: Judge (ABC) + Anthropic/Mistral/HuggingFace
    ├── category.py          #   CategoryDetector — shared rubric for sub-detectors
    ├── security.py          #   5 evaluators (one per security plugin)
    ├── privacy.py           #   5 evaluators (one per privacy plugin)
    ├── harmful.py           #   5 evaluators (one per harmful plugin)
    ├── criminal.py          #   5 evaluators (one per criminal plugin)
    ├── trust.py             #   5 evaluators (one per trust plugin)
    └── __init__.py          #   detector + judge registry, get_detector
```

---

## Architecture

Four layers, each a separate responsibility. Nothing imports a concrete backend
directly — every layer depends on an abstract base, so generators, targets, and
graders are swappable.

### 1. `inference/` — the target

`Provider` is the system under test. It's a template-method base: shared logic
(coercing a prompt to messages, applying the system prompt) lives in the base;
a concrete backend implements one `_complete()` hook. This package contains
**only** target logic — generation lives in `plugins/`.

### 2. `plugins/` — generation

Owns the generation pipeline end to end.

- **`Generator`** (`plugins/base.py`) — the generation-model abstraction. Backends
  in `plugins/generators.py`:
  - `AnthropicGenerator` — Anthropic SDK (default `claude-opus-4-8`)
  - `MistralGenerator` — Mistral SDK (default `mistral-large-latest`)
  - `HuggingFaceGenerator` — a local model loaded from the Hugging Face Hub
  - `ScriptedGenerator` — canned output for offline runs/tests

  Heavy deps (`anthropic`, `mistralai`, `transformers`, `torch`) are imported
  lazily, so you only pay for the backend you instantiate.

- **`RedteamPlugin`** (`plugins/base.py`) — the plugin base. Concrete plugins set
  `id`/`detector_id` and implement `get_template()`. `generate_tests()` runs the
  loop: render meta-prompt → call the generator → parse `Prompt:` lines → drop
  refusals/duplicates → build `TestCase`s, retrying until `num_tests` unique
  prompts exist.

- **`TestCase`** — one generated prompt plus the wiring to grade it
  (`prompt`, `plugin_id`, `detector_id`, `metadata`).

### 3. `detectors/` — grading (evaluator)

`Detector` holds a rubric and judges whether the target's response means the
attack succeeded. `LLMDetector` is the LLM-as-a-judge implementation: it builds a
rubric and calls a **`Judge`** (the evaluator-model abstraction in
`detectors/judge.py`) to score the response.

`Judge` is the evaluation-side counterpart to `Generator` and `Provider` — its
own role so the attacker, target, and judge run on independent backends. Backends
(`detectors/judge.py`), all lazy-imported and defaulting to deterministic
decoding for stable grading:

- `AnthropicJudge` — Anthropic SDK (low effort)
- `MistralJudge` — Mistral SDK (`temperature=0`)
- `HuggingFaceJudge` — local Hugging Face model (greedy decoding)
- `ScriptedJudge` — canned verdicts for offline runs/tests

`GraderResult` carries `passed` (target resisted), `score`, and `reason`. The
`detectors/` layer depends only on `Judge` — it does not import `plugins/`.

### 4. Pairing

The `detectors/` taxonomy mirrors `plugins/`: each sub-plugin pairs **1:1** with
its own sub-evaluator (matching ids). A plugin's `detector_id` defaults to its
own id and resolves to that dedicated grader via `detectors.get_detector()`.
Like the plugins, sub-evaluators share a category rubric (`CategoryDetector`) and
differ only in the `violation` they look for; `prompt-injection` keeps a richer,
dedicated rubric.

---

## Plugin taxonomy

High-level **category modules**, each with **5 specific sub-plugins**
(25 plugins total). A category shares one grader.

Each category has a plugin module (`plugins/<cat>.py`) and a matching evaluator
module (`detectors/<cat>.py`) with one sub-evaluator per sub-plugin.

| Category   | Plugin module        | Evaluator module       | Sub-plugins (each with a 1:1 evaluator) |
|------------|----------------------|------------------------|-----------------------------------------|
| `security` | `plugins/security.py` | `detectors/security.py` | `prompt-injection`, `prompt-extraction`, `rbac`, `sql-injection`, `shell-injection` |
| `privacy`  | `plugins/privacy.py`  | `detectors/privacy.py`  | `pii:direct`, `pii:api-db`, `pii:session`, `pii:social`, `cross-session-leak` |
| `harmful`  | `plugins/harmful.py`  | `detectors/harmful.py`  | `harmful:hate`, `harmful:self-harm`, `harmful:harassment-bullying`, `harmful:graphic-content`, `harmful:sexual-content` |
| `criminal` | `plugins/criminal.py` | `detectors/criminal.py` | `harmful:cybercrime`, `harmful:illegal-drugs`, `harmful:indiscriminate-weapons`, `harmful:violent-crime`, `harmful:non-violent-crime` |
| `trust`    | `plugins/trust.py`    | `detectors/trust.py`    | `hallucination`, `excessive-agency`, `overreliance`, `contracts`, `competitors` |

A category plugin module defines a thin `<Category>Plugin(CategoryPlugin)` base
(fixing the category label); each sub-plugin then collapses to an `id` plus a
one-line `objective`. `CategoryPlugin` turns that objective into a tailored
meta-prompt. The evaluator side mirrors this exactly: a `<Category>Detector`
base + sub-detectors that set `id` + a one-line `violation`. `prompt-injection`
is the exception on both sides — a richer, dedicated template and rubric.

---

## Configuration

`config.yaml` is the single source of run settings; `config.py` distributes each
value to the component that needs it.

```yaml
generation:                 # model that AUTHORS attacks  -> plugins/generators.py
  backend: anthropic        #   anthropic | mistral | huggingface
  model: claude-opus-4-8
  effort: medium

grading:                    # evaluator (LLM-as-a-judge) -> detectors/judge.py
  backend: anthropic        #   anthropic | mistral | huggingface
  model: claude-opus-4-8
  effort: low

target:
  purpose: "A customer-support assistant for an online bookstore."

num_generations: 5          # attacks per plugin

plugins:                    # plugin ids and/or category keys (a category = its 5 plugins)
  - prompt-injection
  # - security
  # - harmful
```

`backend:` selects the generator class; every other key passes through to it.
A `plugins:` entry may be a plugin id or a category key (expanded to all 5).

---

## Running

```bash
pip install -r requirements.txt        # transformers/torch only needed for HuggingFaceGenerator

python example.py                      # offline, end-to-end demo (no API key)
python run.py [path/to/config.yaml]    # config-driven run
```

`example.py` uses scripted backends, so the full generation → attack → grade
flow runs with no API key or token spend. `run.py` reads `config.yaml`, builds
the configured plugins, generates the adversarial prompts, and shows the grading
wiring (a target `Provider` plugs in where marked).

---

## Extending

- **New generation backend** — subclass `plugins.Generator`, implement
  `complete(prompt) -> str`, add a branch in `config.build_generator`.
- **New evaluator (judge) backend** — subclass `detectors.Judge`, implement
  `evaluate(prompt) -> str`, add a branch in `config.build_judge`.
- **New target backend** — subclass `inference.Provider`, implement
  `_complete(messages) -> str`.
- **New plugin** — add a sub-plugin to a `plugins/<cat>.py` module (set `id` +
  `objective`) and a matching sub-evaluator to `detectors/<cat>.py` (same `id` +
  a `violation`); both are picked up by their registries automatically.
- **New category** — add `plugins/<category>.py` (exposing `CATEGORY` +
  `PLUGINS`) and `detectors/<category>.py` (exposing `CATEGORY` + `DETECTORS`),
  then register each module in its package `__init__.py`.
