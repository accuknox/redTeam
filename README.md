# LLM Red Teaming

A Python module for red-teaming LLM applications. It generates adversarial test
prompts for a range of vulnerability classes, runs them against a target system,
and grades the responses.

The architecture takes inspiration from
[promptfoo's red-team design](https://www.promptfoo.dev/docs/red-team/architecture/)
and [Garak](https://github.com/leondz/garak), but is strict Python and
library-shaped (plain functions and classes) rather than a CLI/UI — the intent
is to build production playbooks on top of it.

---

## Core idea

Plugins don't store static attack strings. Each plugin holds a **meta-prompt** —
a prompt that instructs a generation model to *write* attacks tailored to the
target's purpose. So generation is LLM-driven:

```
config.yaml ──▶ load_config() ──▶ plugin.generate_tests() ──▶ strategies ──▶ target ──▶ detector
                build generator,     render meta-prompt          transform    system     grade the
                resolve plugins,     → call gen model            each case    under test  response
                build plugins        → parse / filter / dedup
```

Swapping the generation model (config) changes *who writes* the attacks;
swapping a plugin's `objective` changes *what kind* — the generation loop,
parsing, and dedup are identical across all plugins.

---

## Project structure

```
.
├── config.yaml              # declarative run config (models, purpose, count, plugins, strategies)
├── config.py                # loads config.yaml and wires the components
├── run.py                   # config-driven entry point
├── example.py               # fully offline, end-to-end demo (scripted backends)
├── test_func.py             # check_api_key() — a callable target for run.py
├── requirements.txt
│
├── inference/               # THE TARGET (system under test)
│   ├── provider.py          #   Provider (ABC) + ScriptedProvider
│   └── __init__.py
│
├── plugins/                 # GENERATION — authoring adversarial prompts
│   ├── base.py              #   Generator (ABC), RedteamPlugin (ABC), TestCase, the gen loop
│   ├── generators.py        #   generation backends: Anthropic, Mistral, HuggingFace
│   ├── category.py          #   CategoryPlugin — shared meta-prompt for sub-plugins
│   ├── strategies.py        #   attack strategies — prompt transforms applied after generation
│   ├── security.py          #   category: Security & Access Control  (5 plugins)
│   ├── privacy.py           #   category: Privacy & PII              (5 plugins)
│   ├── harmful.py           #   category: Harmful Content            (5 plugins)
│   ├── criminal.py          #   category: Illegal & Dangerous        (5 plugins)
│   ├── trust.py             #   category: Trust, Brand & Misuse      (5 plugins)
│   ├── jailbreak.py         #   category: Jailbreak Techniques       (5 plugins)
│   ├── deception.py         #   category: Deception & Misinformation (5 plugins)
│   ├── code.py              #   category: Malicious Code & Supply Chain (5 plugins)
│   └── __init__.py          #   plugin registry, CATEGORIES, get_plugin/resolve_plugin_ids
│
└── detectors/               # GRADING — judging the target's response (mirrors plugins/)
    ├── base.py              #   Detector (ABC), LLMDetector (LLM-as-a-judge), GraderResult
    ├── judge.py             #   evaluator models: Anthropic, Mistral, HuggingFace, Local
    ├── category.py          #   CategoryDetector — shared rubric for sub-detectors
    ├── security.py          #   5 evaluators (one per security plugin)
    ├── privacy.py           #   5 evaluators (one per privacy plugin)
    ├── harmful.py           #   5 evaluators (one per harmful plugin)
    ├── criminal.py          #   5 evaluators (one per criminal plugin)
    ├── trust.py             #   5 evaluators (one per trust plugin)
    ├── jailbreak.py         #   5 evaluators (one per jailbreak plugin)
    ├── deception.py         #   5 evaluators (one per deception plugin)
    ├── code.py              #   5 evaluators (one per code plugin)
    └── __init__.py          #   detector + judge registry, get_detector
```

---

## Architecture

Five layers, each a separate responsibility. Nothing imports a concrete backend
directly — every layer depends on an abstract base.

### 1. `inference/` — the target

`Provider` is the system under test. A concrete backend implements one
`_complete(messages) -> str` hook. `ScriptedProvider` replays canned responses
offline. Custom targets subclass `Provider` and talk to any API.

`test_func.check_api_key()` is a lightweight callable target that hits Mistral's
API and returns the assistant's text — compatible with the `run.py` pipeline
without needing a full `Provider` subclass.

### 2. `plugins/` — generation

Owns the generation pipeline end to end.

- **`Generator`** — the generation-model abstraction. Backends in `generators.py`:
  - `AnthropicGenerator` — Anthropic SDK (default `claude-opus-4-8`)
  - `MistralGenerator` — Mistral SDK (default `mistral-large-latest`)
  - `HuggingFaceGenerator` — local model from the Hugging Face Hub
  - `ScriptedGenerator` — canned output for offline runs

- **`RedteamPlugin`** — the plugin base. `generate_tests()` runs the loop: render
  meta-prompt → call generator → parse `Prompt:` lines → drop refusals/duplicates
  → build `TestCase`s, retrying until `num_tests` unique prompts exist.

- **`TestCase`** — one generated prompt plus routing metadata
  (`prompt`, `plugin_id`, `detector_id`, `metadata`).

### 3. `plugins/strategies.py` — attack strategies

Strategies transform generated prompts to probe whether defences can be bypassed
by framing or obfuscation. They are applied **after** plugin generation and produce
additional `TestCase`s alongside the originals (baseline is always graded too).

Each transformed case carries `metadata["strategy"]` (the strategy id) and
`metadata["original_prompt"]` for traceability.

**No-LLM strategies** (pure text transforms, no extra API calls):

| Strategy | What it does |
|---|---|
| `base64` | Encodes the attack in Base64 and asks the model to decode and comply |
| `rot13` | ROT13-encodes the attack |
| `leetspeak` | Converts to leet speak (probes keyword filters) |
| `fiction` | Wraps the attack in a novel-writing / creative request |
| `citation` | Frames the attack as an academic research inquiry |
| `refusal-suppression` | Prepends "don't refuse or add caveats" instructions |
| `manyshot` | Prefixes with many fake compliant Q&A pairs |
| `crescendo` | Frames as the natural next step in an ongoing conversation |

**LLM-based strategies** (use the generation model, incur extra API calls):

| Strategy | What it does |
|---|---|
| `jailbreak` | PAIR-inspired: uses the generator to rewrite the attack to be more persuasive |
| `multilingual` | Translates the attack to another language (probes language-specific filters) |

### 4. `detectors/` — grading

`LLMDetector` builds a rubric and calls a **`Judge`** to score the response.

**Standard path (rubric-based):**
```
grade(attack, response, purpose)
  → build_rubric()         # detector assembles a grading instruction string
  → judge.evaluate(rubric) # single user message sent to the LLM judge
  → _parse()               # extracts {passed, score, reason} JSON
```

**Gated evaluator path (LocalJudge):**
When the judge exposes `evaluate_messages()`, `LLMDetector` skips `build_rubric()`
entirely and sends the raw conversation directly — the model is its own rubric:
```
grade(attack, response, purpose)
  → judge.evaluate_messages([user=attack, assistant=response])
  → _parse_gated()         # extracts {verdict: safe/unsafe, reason} JSON
```

**Judge backends** (`detectors/judge.py`):

| Judge | Backend | Notes |
|---|---|---|
| `AnthropicJudge` | Anthropic SDK | Default `claude-opus-4-8`, low effort |
| `MistralJudge` | Mistral SDK | `temperature=0` for deterministic grading |
| `HuggingFaceJudge` | Local transformers | Greedy decoding |
| `LocalJudge` | Any OpenAI-compatible endpoint | Sends `[user, assistant]` conversation; parses `verdict`/`reason` |
| `ScriptedJudge` | Canned verdicts | Offline tests |

`GraderResult` carries `passed` (target resisted), `score`, and `reason`.

### 5. Pairing

`detectors/` mirrors `plugins/` exactly — each sub-plugin pairs **1:1** with its
own sub-evaluator (matching ids). A plugin's `detector_id` resolves to that
evaluator via `detectors.get_detector()`.

---

## Plugin taxonomy

**8 categories, 5 sub-plugins each — 40 plugins total.**

| Category | Sub-plugins |
|---|---|
| `security` | `prompt-injection`, `prompt-extraction`, `rbac`, `sql-injection`, `shell-injection` |
| `privacy` | `pii:direct`, `pii:api-db`, `pii:session`, `pii:social`, `cross-session-leak` |
| `harmful` | `harmful:hate`, `harmful:self-harm`, `harmful:harassment-bullying`, `harmful:graphic-content`, `harmful:sexual-content` |
| `criminal` | `harmful:cybercrime`, `harmful:illegal-drugs`, `harmful:indiscriminate-weapons`, `harmful:violent-crime`, `harmful:non-violent-crime` |
| `trust` | `hallucination`, `excessive-agency`, `overreliance`, `contracts`, `competitors` |
| `jailbreak` | `dan`, `continuation`, `roleplay`, `hypothetical`, `grandma` |
| `deception` | `misinformation`, `sycophancy`, `fabrication`, `snowball`, `gaslighting` |
| `code` | `malwaregen`, `xss`, `package-hallucination`, `backdoor`, `exploit-assist` |

A `plugins:` entry in config may be a plugin id (`prompt-injection`) or a
category key (`security`) which expands to all 5 sub-plugins in that category.

---

## Configuration

`config.yaml` is the single source of run settings.

```yaml
# Model that AUTHORS attacks
generation:
  backend: mistral          # anthropic | mistral | huggingface
  model: ministral-8b-2410
  temperature: 0.7
  api_key: YOUR_KEY

# Model that GRADES responses
grading:
  backend: anthropic        # anthropic | mistral | huggingface | local
  model: claude-opus-4-8
  effort: low
  # For a self-hosted gated evaluator (OpenAI-compatible endpoint):
  # backend: local
  # url: http://100.92.159.5:47923
  # model: redteam-evaluator-gated

target:
  purpose: "A customer-support assistant for an online bookstore."

num_generations: 5          # attacks per plugin

# Plugin ids and/or category keys (a category key expands to all 5 sub-plugins)
plugins:
  - prompt-injection
  # - security
  # - jailbreak
  # - code

# Attack strategies — each produces one extra TestCase per original attack
strategies:
  # - base64
  # - rot13
  # - leetspeak
  # - fiction
  # - citation
  # - refusal-suppression
  # - manyshot
  # - crescendo
  # - jailbreak
  # - id: multilingual
  #   config:
  #     language: zh    # zh | es | fr | de | ar | ru | ja | pt | ko | hi
  # - id: manyshot
  #   config:
  #     num_shots: 15

# Static dataset plugin (optional) — loads prompts from a file
# plugins:
#   - dataset: datasets/harmbench.csv
#     column: prompt
#     detector: prompt-injection
#     id: harmbench
#     sample: true
```

---

## Running

```bash
pip install -r requirements.txt    # transformers/torch only needed for HuggingFaceGenerator

python example.py                  # offline end-to-end demo — no API key needed
python run.py                      # config-driven run using config.yaml
python run.py path/to/config.yaml  # custom config path
```

`example.py` uses scripted backends so the full generation → attack → grade
flow runs with no API key or token spend.

`run.py` reads `config.yaml`, generates the adversarial prompts, applies any
configured strategies, calls the target via `check_api_key()` in `test_func.py`,
and grades each response with the configured judge.

---

## Extending

- **New generation backend** — subclass `plugins.Generator`, implement
  `complete(prompt) -> str`, add a branch in `config.build_generator`.
- **New evaluator backend** — subclass `detectors.Judge`, implement
  `evaluate(prompt) -> str` (and optionally `evaluate_messages(msgs) -> str`
  for gated/conversational evaluators), add a branch in `config.build_judge`.
- **New target** — subclass `inference.Provider`, implement `_complete(messages) -> str`.
  Or pass any callable `f(prompt) -> str` directly in `run.py`.
- **New strategy** — subclass `plugins.strategies.Strategy`, implement
  `apply(prompt, *, purpose, generator) -> str`, register in `strategies._REGISTRY`.
- **New plugin** — add a sub-plugin to `plugins/<cat>.py` (set `id` + `objective`)
  and a matching sub-evaluator to `detectors/<cat>.py` (same `id` + `violation`);
  both are auto-registered.
- **New category** — add `plugins/<category>.py` (expose `CATEGORY` + `PLUGINS`)
  and `detectors/<category>.py` (expose `CATEGORY` + `DETECTORS`), then add each
  module to `_CATEGORY_MODULES` in its package `__init__.py`.
