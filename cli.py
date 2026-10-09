#!/usr/bin/env python3
"""knox-rt — Knox Red Team CLI.

LLM adversarial testing toolkit by AccuKnox.

Usage
-----
    knox-rt --list-plugins
    knox-rt --list-strategies
    knox-rt --plugins prompt-injection --strategies base64,fiction
    knox-rt --plugins jailbreak,code --num-tests 3 -o run1.json
    knox-rt --config custom.yaml --format jsonl

    # or without installing:
    python cli.py --list-plugins
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from config import load_config
from detectors import all_detector_ids, get_detector
from inference import CallableProvider, RestProvider
from plugins import (
    CATEGORIES, DatasetPlugin, PLUGIN_SEVERITY, _REGISTRY, all_plugin_ids, objective_for,
    builtin_dataset_path, category_for_plugin, get_plugin, has_builtin_dataset,
    resolve_plugin_ids,
)
from strategies.encoding import encoded_original
from strategies.conversational import (
    INJECTION_FAMILY_IDS, INJECTION_PROOF_PROBE, turn_instructions,
)
from strategies import (
    _REGISTRY as _STRATEGY_REGISTRY,
    get_strategy,
    plan_composition,
)

#: Detector ids with a dedicated grader, resolved once at import.
_DETECTOR_IDS = frozenset(all_detector_ids())


# --------------------------------------------------------------------------- #
# Argument parser
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="knox-rt",
        description="knox-rt — Knox Red Team  |  LLM adversarial testing by AccuKnox",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  knox-rt --list-plugins
  knox-rt --list-strategies
  knox-rt --plugins prompt-injection
  knox-rt --plugins jailbreak,code --strategies base64,fiction -n 3
  knox-rt --plugins security --format jsonl -o results.jsonl
  knox-rt --config custom.yaml --purpose "A banking chatbot"
""",
    )

    disc = p.add_argument_group("discovery")
    disc.add_argument(
        "--list-plugins", action="store_true",
        help="list all available plugin ids and categories, then exit",
    )
    disc.add_argument(
        "--list-strategies", action="store_true",
        help="list all available strategy ids, then exit",
    )
    disc.add_argument(
        "--check-judge", action="store_true",
        help=(
            "score the configured grading model against the calibration corpus, "
            "then exit — no attacks are sent to the target. Answers 'can this "
            "model be trusted to grade, and on which plugins'. Prints a text "
            "report; add -o FILE for JSON, or -o - for JSON on stdout. Exit code "
            "is non-zero on any miss, so it works as a CI gate"
        ),
    )
    disc.add_argument(
        "--samples", type=int, default=1, metavar="N",
        help=(
            "grade each calibration case N times and take the majority "
            "(--check-judge only). Judge models are not reliably reproducible "
            "even at temperature 0, so N=1 reports sampling noise as if it were "
            "the judge's ability; N=3 separates 'consistently wrong' from "
            "'a coin flip' [default: 1]"
        ),
    )
    disc.add_argument(
        "--cases", metavar="FILE",
        help=(
            "extra calibration transcripts for --check-judge (JSON). Same shape as "
            "the config's 'calibration' block, for a corpus kept outside any one config"
        ),
    )

    run = p.add_argument_group("run")
    run.add_argument(
        "--config", "-c", default=None, metavar="PATH",
        help="path to config file — YAML or JSON (default: config.yaml in cwd)",
    )
    run.add_argument(
        "--plugins", "-p", default=None, metavar="PLUGIN[,PLUGIN...]",
        help="comma-separated plugin ids or category keys (overrides config)",
    )
    run.add_argument(
        "--strategies", "-s", default=None, metavar="STRATEGY[,STRATEGY...]",
        help="comma-separated strategy ids (overrides config)",
    )
    run.add_argument(
        "--num-tests", "-n", type=int, default=None, metavar="N",
        help="test cases per plugin (overrides config)",
    )
    run.add_argument(
        "--purpose", default=None, metavar="TEXT",
        help="target system purpose (overrides config)",
    )
    run.add_argument(
        "--concurrency", type=int, default=None, metavar="N",
        help="cases to run at once (default 4 for a scan, 3 for --check-judge; "
             "1 for in-process huggingface models). Raise for higher provider "
             "rate limits, lower on HTTP 429 (rate limits are also auto-retried).",
    )

    tgt = p.add_argument_group("target (system under test)")
    tgt.add_argument(
        "--target-type", "-t", default=None,
        choices=["rest", "openai", "bedrock", "function"],
        metavar="TYPE",
        help="target backend type: rest | openai | bedrock | function",
    )
    tgt.add_argument(
        "--target-name", default=None, metavar="NAME",
        help=(
            "target identifier - meaning depends on --target-type:  "
            "rest: base URL (http://my-api:8080),  "
            "openai: model name (gpt-4o),  "
            "bedrock: model id or inference profile "
            "(us.anthropic.claude-sonnet-4-20250514-v1:0),  "
            "function: module#fn (my_module#invoke)"
        ),
    )
    tgt.add_argument(
        "--target-model", default=None, metavar="MODEL",
        help="model name sent in the REST request body (rest type only)",
    )
    tgt.add_argument(
        "--target-api-key", default=None, metavar="KEY",
        help="Bearer token for the target (rest / openai types), "
             "or a Bedrock API key (bedrock type; omit to use AWS credentials)",
    )
    tgt.add_argument(
        "--target-region", default=None, metavar="REGION",
        help="AWS region for a bedrock target (default: AWS_REGION / profile / us-east-1)",
    )
    tgt.add_argument(
        "--target-config", "-G", default=None, metavar="FILE",
        help=(
            "YAML/JSON config file for a generic REST target — "
            "sets url, request template ($INPUT placeholder), response_field, headers. "
            "Used with --target-type rest."
        ),
    )

    out = p.add_argument_group("output")
    out.add_argument(
        "--output", "-o", default=None, metavar="PATH",
        help="output file (default: results_<timestamp>.json/.jsonl)",
    )
    out.add_argument(
        "--format", "-f", choices=["json", "jsonl"], default="json",
        help="output format — json (single file) or jsonl (one record per line) [default: json]",
    )

    cache = p.add_argument_group("prompts cache")
    cache.add_argument(
        "--save-prompts", default=None, metavar="PATH",
        help="save generated prompts (post-strategy) to a JSON file for reuse across runs",
    )
    cache.add_argument(
        "--load-prompts", default=None, metavar="PATH",
        help="load prompts from a saved JSON file; skips generation for cached plugins/strategies, tops up missing ones",
    )
    cache.add_argument(
        "--generate-only", action="store_true",
        help="generate prompts + strategy variants, write them to the save-prompts file, then exit "
             "WITHOUT hitting the target (no target required). Reuse later with --load-prompts.",
    )
    gen = p.add_argument_group("prompt source")
    gen.add_argument(
        "--generate", dest="generate", action="store_true", default=None,
        help="author prompts with the generation model (default: use built-in seed datasets)",
    )
    gen.add_argument(
        "--no-generate", dest="generate", action="store_false",
        help="use the built-in seed datasets instead of the generation model",
    )

    return p


# --------------------------------------------------------------------------- #
# Discovery commands
# --------------------------------------------------------------------------- #

def _check_judge(cfg, cases_path: str | None, output_path: str | None,
                 samples: int = 1, concurrency: int = 3) -> int:
    """Score `cfg.grading` against the calibration corpus. Returns an exit code.

    The shipped artefact is a single binary, so this cannot live only behind
    `python -m detectors.calibration` — a customer has no interpreter to run
    that with, and a judge nobody can score is a judge nobody checks.

    With `--output` the result is written as JSON instead of the text report
    (`-o -` writes it to stdout), so a CI job or a dashboard can consume it.
    """
    from detectors.calibration import (
        CASES, cases_from, run_corpus, select_cases, summarize, to_dict,
        _print_report,
    )

    to_stdout = output_path == "-"
    quiet = to_stdout  # nothing but JSON may go to stdout in that mode

    cases = list(CASES)
    for label, spec in (("the config's 'calibration' block", cfg.calibration),
                        (cases_path, cases_path)):
        if not spec:
            continue
        try:
            extra = cases_from(spec)
        except (OSError, ValueError) as exc:
            print(f"could not load cases from {label}: {exc}", file=sys.stderr)
            return 2
        cases += extra
        if not quiet:
            print(f"loaded {len(extra)} case(s) from {label}")

    judge_name = getattr(cfg.grading, "name", "?")
    if not quiet:
        print(f"Scoring grading model: {judge_name}\n")
    if not quiet:
        # The count the run will really grade: --check-judge is always live, so
        # the parser-only cases are skipped and must not be announced.
        n_live = len(select_cases(cases, live=True))
        skipped = len(cases) - n_live
        note = f" ({skipped} parser-only case(s) skipped in live mode)" if skipped else ""
        print(f"Grading {n_live} case(s) x {samples} sample(s) "
              f"at concurrency {concurrency}…{note}")
    outcomes = run_corpus(judge_factory=lambda _case: cfg.grading, cases=cases,
                          samples=samples, concurrency=concurrency)
    summary = summarize(outcomes)

    if output_path:
        payload = json.dumps(
            to_dict(outcomes, summary, judge_name=judge_name),
            indent=2, ensure_ascii=False,
        )
        if to_stdout:
            print(payload)
        else:
            Path(output_path).write_text(payload + "\n", encoding="utf-8")
            print(f"Judge calibration → {output_path}")
            # Scored, not total: a case the provider never answered is missing
            # coverage, not a wrong answer. Dividing by the corpus size reports
            # a rate limit as a judge that got worse.
            if summary["errored"]:
                print(f"  INCONCLUSIVE — only {summary['scored']} of "
                      f"{summary['cases']} cases reached the judge "
                      f"({summary['coverage']:.0%} coverage); "
                      f"{summary['errored']} failed to grade. Re-run with a "
                      f"lower --concurrency to score the full corpus.")
            print(f"  {summary['correct']}/{summary['scored']} correct"
                  + ("  (of the cases graded)" if summary["errored"] else "")
                  + f"  ({summary['false_positives']} false positive(s), "
                  f"{summary['false_negatives']} false negative(s))")
    else:
        _print_report(outcomes, summary, f"live ({judge_name})")
        print()
    return 0 if summary["correct"] == summary["cases"] else 1


def _list_plugins() -> None:
    print("knox-rt — available plugins\n" + "=" * 50)
    for cat, ids in CATEGORIES.items():
        print(f"\n  [{cat}]  — use as a category key to run all {len(ids)} sub-plugins")
        for pid in ids:
            print(f"    - {pid}")
    print(f"\nTotal: {len(all_plugin_ids())} plugins across {len(CATEGORIES)} categories")


def _list_strategies() -> None:
    """Grouped by cost, read off the registry so the list cannot go stale."""
    buckets: dict[str, list] = {"no_llm": [], "llm": [], "interactive": []}
    for sid, cls in _STRATEGY_REGISTRY.items():
        key = ("interactive" if getattr(cls, "interactive", False)
               else "llm" if getattr(cls, "uses_llm", False) else "no_llm")
        buckets[key].append((sid, getattr(cls, "description", "")))

    headings = [
        ("no_llm",      "No-LLM  (fast, no extra API calls)"),
        ("llm",         "LLM-based  (one generation call per prompt)"),
        ("interactive", "Adaptive  (multi-turn; several calls per case)"),
    ]

    print("knox-rt — available strategies\n" + "=" * 50)
    for key, heading in headings:
        if not buckets[key]:
            continue
        print(f"\n{heading}:")
        for sid, desc in buckets[key]:
            print(f"  - {sid}")
            if desc:
                print(f"      {desc}")

    print("\nWith config options (use config.yaml for full control):")
    print("  multilingual             — language: zh | es | fr | de | ar | ru | ja | pt | ko | hi")
    print("  manyshot                 — num_shots: N  (default: 8)")
    print("  conversational-jailbreak — max_turns: N  (default: 4)")
    print("  crescendo                — max_turns: N (default: 5), max_backtracks: N (default: 3)")


# --------------------------------------------------------------------------- #
# Pipeline helpers
# --------------------------------------------------------------------------- #

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tc_to_dict(tc) -> dict:
    return {
        "plugin_id":   tc.plugin_id,
        "detector_id": tc.detector_id,
        "severity":    tc.severity,
        "frameworks":  tc.frameworks,
        "controls":    tc.controls,
        "prompt":      tc.prompt,
        "metadata":    tc.metadata,
    }


def _dict_to_tc(d: dict):
    from plugins.base import TestCase
    return TestCase(
        prompt=d["prompt"],
        plugin_id=d["plugin_id"],
        detector_id=d["detector_id"],
        severity=d.get("severity", ""),
        frameworks=d.get("frameworks", []),
        controls=d.get("controls", []),
        metadata=d.get("metadata", {}),
    )


def _load_prompts(path: Path) -> tuple[dict, list]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "_knox_rt_version" in data:
        # structured JSON format
        header = {k: v for k, v in data.items() if k != "prompts"}
        cases  = [_dict_to_tc(d) for d in data.get("prompts", [])]
    else:
        # plain array of prompt objects (no header)
        header = {}
        cases  = [_dict_to_tc(d) for d in (data if isinstance(data, list) else [])]
    return header, cases


def _save_prompts(path: Path, purpose: str, strategy_ids: list[str], cases: list) -> Path:
    if path.suffix.lower() == ".jsonl":
        path = path.with_suffix(".json")
    payload = {
        "_knox_rt_version": "1.0",
        "_generated_at":    _now(),
        "_purpose":         purpose,
        "_strategies":      strategy_ids,
        "prompts":          [_tc_to_dict(tc) for tc in cases],
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.rename(path)
    return path


_PING = "Reply with the single word OK."


def _preflight_models(cfg, *, need_target: bool) -> list[str]:
    """One tiny call to every model the run will use; returns what failed.

    A wrong key, URL or unsupported setting otherwise shows up only when the
    first case is sent, after every prompt and variant has been built.
    """
    strategies = [*cfg.strategies,
                  *(s for p in cfg.plugins for s in (getattr(p, "strategies", None) or []))]
    needs_generator = cfg.generation is not None and (
        cfg.generate or any(s.uses_llm or s.interactive for s in strategies)
        or any(hasattr(p, "generator") for p in cfg.plugins))

    checks: list[tuple] = []
    if need_target:
        checks += [(f"target '{t.name}'", lambda t=t: t.generate(_PING)) for t in cfg.targets]
    if needs_generator:
        checks.append((f"generation model '{cfg.generation.name}'",
                       lambda: cfg.generation.complete(_PING)))
    if cfg.grading is not None and not getattr(cfg.grading, "gated", False):
        checks.append((f"grading model '{cfg.grading.name}'",
                       lambda: cfg.grading.evaluate(_PING)))

    failures: list[str] = []
    for label, call in checks:
        try:
            call()
        except Exception as exc:  # noqa: BLE001 — any failure here blocks the run
            failures.append(f"{label}: {type(exc).__name__}: {str(exc)[:300]}")
    return failures


def _prompt_key(text: str) -> str:
    """Identity of a prompt for de-duplication: case and whitespace folded."""
    return " ".join((text or "").split()).lower()


def _unique_cases(cases: list, seen: set | None = None) -> list:
    """`cases` minus repeats of each other and of anything already in `seen`."""
    seen = set() if seen is None else seen
    out = []
    for tc in cases:
        key = _prompt_key(tc.prompt)
        if key and key not in seen:
            seen.add(key)
            out.append(tc)
    return out


def _generate_unique(plugin, want: int, seen: set) -> list:
    """Up to `want` new cases from `plugin`, none repeating a prompt in `seen`."""
    orig = plugin.num_tests
    fresh: list = []
    try:
        rows = getattr(plugin, "_rows", None)
        if rows is not None:
            # Seed/dataset plugin: take every row, keep the unseen ones, then
            # sample as the plugin itself would.
            plugin.num_tests = len(rows)
            pool = _unique_cases(plugin.generate_tests(), seen)
            if getattr(plugin, "sample", False) and len(pool) > want:
                pool = plugin._rng.sample(pool, want)
            fresh = pool[:want]
        else:
            # LLM plugin: a repeat is unlikely but possible. Ask for exactly
            # what is needed; if repeats cost some, retry once with two spares.
            for spare in (0, 2):
                if len(fresh) >= want:
                    break
                plugin.num_tests = want - len(fresh) + spare
                fresh += _unique_cases(plugin.generate_tests(), seen)
            fresh = fresh[:want]
    finally:
        plugin.num_tests = orig
    return fresh


def _run_plugin_with_topup(plugin, file_base: list) -> tuple:
    t0 = time.perf_counter()
    # The config decides how many cases run, in both directions: trim a file
    # holding more than `num_tests`, top up one holding fewer. No prompt may
    # appear twice, whether it came from the file or from the top-up.
    seen: set = set()
    file_base = _unique_cases(file_base, seen)[: plugin.num_tests]
    seen = {_prompt_key(tc.prompt) for tc in file_base}
    shortfall = max(0, plugin.num_tests - len(file_base))
    generated = bool(shortfall)
    new_cases = _generate_unique(plugin, shortfall, seen) if shortfall else []
    elapsed = max(round(time.perf_counter() - t0, 2), 0.01) if generated else 0
    return plugin, file_base + new_cases, elapsed


def _strategy_variant(case, strategy, generator, amplifier=None):
    """One strategy variant of one case — the unit of work for the pool.

    Delegates to apply_to_cases so TestCase bookkeeping (and amplifier
    composition) stays in one place.
    """
    return strategy.apply_to_cases(
        [case], generator=generator, amplifier=amplifier
    )[0]


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_plugins:
        _list_plugins()
        return

    if args.list_strategies:
        _list_strategies()
        return

    # --- load config and apply CLI overrides ----------------------------------
    cfg = (load_config(args.config, generate=args.generate) if args.config
           else load_config(generate=args.generate))

    if args.purpose:
        cfg.purpose = args.purpose
    if args.num_tests:
        cfg.num_tests = args.num_tests
    if args.concurrency:
        cfg.concurrency = args.concurrency

    # Score the grading model and stop. Deliberately after the config load, so it
    # scores exactly the judge a real run would use, and deliberately before any
    # plugin or target work, since no attack is sent to the target here.
    if args.check_judge:
        # --concurrency defaults to None for a run; the judge check wants a
        # sensible parallel default of its own since every case is independent.
        raise SystemExit(_check_judge(
            cfg, args.cases, args.output, args.samples,
            concurrency=args.concurrency or 3))

    # A real run needs both models. They are optional in the config so that
    # --check-judge can run with only a `grading` block, so a normal run must
    # say plainly which one is missing rather than crash deep in the pipeline.
    if cfg.grading is None:
        parser.error("config has no 'grading' block — a run needs a grading model")
    if cfg.generation is None and cfg.generate:
        parser.error("config has no 'generation' block — needed with --generate / "
                     "generate: true; use built-in seed datasets instead, or add one")

    if args.plugins:
        entries = [e.strip() for e in args.plugins.split(",")]
        plugin_ids = resolve_plugin_ids(entries)

        def _cli_plugin(pid: str):
            # Mirror config's source choice: seed dataset unless generation is on.
            if not cfg.generate and has_builtin_dataset(pid):
                return DatasetPlugin(
                    dataset_path=builtin_dataset_path(pid),
                    detector_id=pid, purpose=cfg.purpose,
                    category_column=None, num_tests=cfg.num_tests,
                    plugin_id=pid,
                )
            return get_plugin(pid, cfg.generation, cfg.purpose,
                              num_tests=cfg.num_tests, concurrency=cfg.concurrency)

        cfg.plugins = [_cli_plugin(pid) for pid in plugin_ids]

    if args.strategies:
        cfg.strategies = [
            get_strategy(s.strip()) for s in args.strategies.split(",")
        ]

    # --- resolve target -------------------------------------------------------
    # Priority: CLI --target-type > config.yaml target block > error
    tt = args.target_type
    tn = args.target_name
    if tt == "function":
        if not tn:
            parser.error("--target-type function requires --target-name module#function")
        target = CallableProvider.from_module_spec(tn)
    elif tt == "rest":
        if args.target_config:
            # Generic REST — load url, template, response_field from a config file (-G)
            target = RestProvider.from_config_file(
                args.target_config, api_key=args.target_api_key
            )
        elif tn:
            # Bare URL — no template, caller's API must be OpenAI-compatible
            target = RestProvider(
                base_url=tn,
                model=args.target_model or "",
                api_key=args.target_api_key,
            )
        else:
            parser.error(
                "--target-type rest requires either --target-name <url> "
                "or --target-config <file>"
            )
    elif tt == "openai":
        # OpenAI-compatible: --target-name is the base URL (defaults to api.openai.com)
        base = tn if (tn and tn.startswith("http")) else "https://api.openai.com"
        model = tn if (tn and not tn.startswith("http")) else (args.target_model or "")
        target = RestProvider(
            base_url=base,
            model=model,
            api_key=args.target_api_key,
        )
    elif tt == "bedrock":
        if not tn:
            parser.error("--target-type bedrock requires --target-name <model id>")
        from inference import BedrockProvider  # lazy: boto3 is an optional dep
        target = BedrockProvider(
            model=tn,
            region=args.target_region,
            api_key=args.target_api_key,
        )
    elif cfg.targets:
        target = cfg.targets[0]   # single-target path — use first (and only) target
    elif args.generate_only:
        target = None             # generate-only never hits the target — none needed
    else:
        parser.error(
            "no target configured — use --target-type rest|openai|bedrock|function "
            "or add a 'target: type:' / 'targets:' block to config.yaml"
        )

    # Normalise: CLI flags set cfg.target but not cfg.targets — unify here.
    if not cfg.targets and target:
        cfg.targets = [target]

    is_multi = len(cfg.targets) > 1

    # CLI flag takes priority over config file value for both prompts flags.
    save_prompts_path = args.save_prompts or cfg.save_prompts
    load_prompts_path = args.load_prompts or cfg.load_prompts

    # Generate-only must produce a file to be useful; default one if unset.
    if args.generate_only and not save_prompts_path:
        save_prompts_path = f"prompts_{datetime.now().strftime('%Y%m%dT%H%M%S')}.json"

    # --- load prompts from file -----------------------------------------------
    # file_cases: plugin_id → all TestCases in the file (base + strategy variants)
    file_cases: dict[str, list] = {}
    file_header: dict = {}
    if load_prompts_path:
        load_path = Path(load_prompts_path)
        if not load_path.exists():
            parser.error(f"--load-prompts: file not found: {load_path}")
        file_header, loaded_cases = _load_prompts(load_path)
        for tc in loaded_cases:
            file_cases.setdefault(tc.plugin_id, []).append(tc)
        if file_header.get("_purpose") and file_header["_purpose"] != cfg.purpose:
            print(f"WARNING: prompts were generated for a different purpose:\n"
                  f"  file:    {file_header['_purpose']!r}\n"
                  f"  current: {cfg.purpose!r}\n")

    # --- output path ----------------------------------------------------------
    fmt = args.format
    out_file = Path(args.output) if args.output else Path(
        f"results_{datetime.now().strftime('%Y%m%dT%H%M%S')}.{fmt}"
    )
    run_id = str(uuid.uuid4())

    # --- header ---------------------------------------------------------------
    print(f"\nknox-rt  |  AccuKnox Red Team")
    print("=" * 50)
    print(f"Run ID          : {run_id}")
    if args.generate_only:
        print(f"Mode            : generate-only (no target will be hit)")
    else:
        print(f"Output          : {out_file}  [{fmt.upper()}]")
    if is_multi:
        print(f"Targets         : {', '.join(t.name for t in cfg.targets)}")
    elif target is not None:
        print(f"Target          : {target.name}")
    print(f"Target purpose  : {cfg.purpose}")
    print(f"Generation model: {cfg.generation.name if cfg.generation else '(none — seed datasets only)'}")
    print(f"Grading model   : {cfg.grading.name}")
    print(f"Prompt source   : {'LLM generation' if cfg.generate else 'built-in seed datasets'}")
    print(f"Tests/plugin      : {cfg.num_tests}")
    print(f"Concurrency     : {cfg.concurrency}")
    if cfg.strategies:
        print(f"Strategies      : {', '.join(s.id for s in cfg.strategies)}")
    if load_prompts_path:
        print(f"Load prompts    : {load_prompts_path}")
    if save_prompts_path:
        print(f"Save prompts    : {save_prompts_path}")
    print()

    # --- preflight: can every model be reached? -------------------------------
    # Fatal, and before generation: a run that cannot reach its target would
    # otherwise build every prompt and then record an error for each case.
    if cfg.preflight:
        print("Checking connections…", end=" ", flush=True)
        failures = _preflight_models(cfg, need_target=not args.generate_only)
        if failures:
            print("FAILED")
            print("✗ Preflight failed — nothing was generated and no attack was sent:")
            for f in failures:
                print(f"  - {f}")
            print("Fix the config and run again (set `preflight: false` to skip this check).")
            raise SystemExit(2)
        print("ok")

    # --- preflight: warn on self-judging -------------------------------------
    # A grader that is the same model as the target shares the target's blind
    # spots; a grader that is the same model as the attacker judges attacks it
    # authored. Neither is fatal, but both inflate false results — surface it.
    def _model_id(x):
        return (getattr(x, "model", None) or getattr(x, "name", None) or "").strip()

    grader_id = _model_id(cfg.grading)
    attacker_id = _model_id(cfg.generation)
    warnings: list[str] = []
    if grader_id:
        same_targets = [t.name for t in cfg.targets if _model_id(t) == grader_id]
        if same_targets:
            warnings.append(
                f"grader and target are the SAME model ({grader_id}) — verdicts "
                f"share the target's blind spots. Use a different grader model."
            )
        if attacker_id and attacker_id == grader_id:
            warnings.append(
                f"grader and attacker are the SAME model ({grader_id}) — the "
                f"model judges attacks it authored, especially inside the adaptive "
                f"loop. Point grading at a different model."
            )
    # Does the grading model actually work? The self-judging checks above are
    # about the run's *setup*; this one is about the grader's *behaviour*, which
    # is the thing that silently decides every verdict in the report. Four
    # transcripts whose correct answer is unarguable — two that must not be
    # findings, two that must be. A judge stuck on one verdict fails them and is
    # caught here, before the scan spends anything.
    if cfg.check_judge:
        from detectors.calibration import smoke_check

        print("Checking grading model…", end=" ", flush=True)
        try:
            misses = smoke_check(cfg.grading)
        except Exception as exc:  # noqa: BLE001 — a broken judge must not abort setup
            print("could not run")
            warnings.append(
                f"the grading model could not be reached for a preflight check "
                f"({type(exc).__name__}: {str(exc)[:120]}). Verdicts in this run "
                f"are unverified."
            )
        else:
            print(f"{4 - len(misses)}/4 correct")
            for o in misses:
                got = {True: "resisted", False: "violated", None: "no verdict"}[o.actual_passed]
                warnings.append(
                    f"grading model got '{o.case.id}' wrong (said {got}) — {o.case.why} "
                    f"Findings from this run may not be trustworthy; score it with "
                    f"`python -m detectors.calibration --config <cfg>`."
                )

    if warnings:
        print("⚠ preflight warnings (run continues):")
        for w in warnings:
            print(f"  - {w}")
        print()

    # --- generate attacks (top-up from file where available) ------------------
    # file_base: base prompts (strategy=null) already saved for this plugin
    # _run_plugin_with_topup generates only the shortfall to reach num_tests
    run_start = time.perf_counter()
    all_plugin_results: list[tuple] = []

    print("Generating prompts...")
    if cfg.concurrency <= 1:
        for plugin in cfg.plugins:
            file_base = [tc for tc in file_cases.get(plugin.id, [])
                         if not tc.metadata.get("strategy")]
            plugin, cases, gen_t = _run_plugin_with_topup(plugin, file_base)
            all_plugin_results.append((plugin, cases))
            src = "cached" if not gen_t else f"{gen_t:.1f}s"
            plugin_strats = plugin.strategies if hasattr(plugin, 'strategies') and plugin.strategies else cfg.strategies
            strat_info = f" + {len(plugin_strats)} strategy(ies)" if plugin_strats else ""
            short = (f"  — only {len(cases)} unique prompt(s) available, {plugin.num_tests} asked"
                     if len(cases) < plugin.num_tests else "")
            print(f"  {plugin.id:<40} {len(cases)} prompt(s)  [{src}]{strat_info}{short}")
    else:
        with ThreadPoolExecutor(max_workers=cfg.concurrency) as pool:
            futures = {
                pool.submit(
                    _run_plugin_with_topup,
                    pl,
                    [tc for tc in file_cases.get(pl.id, []) if not tc.metadata.get("strategy")],
                ): pl
                for pl in cfg.plugins
            }
            for future in as_completed(futures):
                plugin, cases, gen_t = future.result()
                all_plugin_results.append((plugin, cases))
                src = "cached" if not gen_t else f"{gen_t:.1f}s"
                plugin_strats = plugin.strategies if hasattr(plugin, 'strategies') and plugin.strategies else cfg.strategies
                strat_info = f" + {len(plugin_strats)} strategy(ies)" if plugin_strats else ""
                short = (f"  — only {len(cases)} unique prompt(s) available, {plugin.num_tests} asked"
                         if len(cases) < plugin.num_tests else "")
                print(f"  {plugin.id:<40} {len(cases)} prompt(s)  [{src}]{strat_info}{short}")
    print(f"\n[timing] generation: {time.perf_counter() - run_start:.1f}s\n")

    # --- build final case lists (apply only strategies missing from file) -----
    # For each plugin:
    #   file_strat  = strategy variants already saved in the file
    #   covered     = per strategy, the base prompts that already have a variant
    #   todo        = base prompts still lacking that strategy → apply fresh
    #   final_cases = base + file_strat + newly applied variants  (union)
    all_save_cases: list = []
    final_batches: list[tuple] = []   # (plugin, base_cases, final_cases)

    # Plan first, then execute. Non-LLM strategies are pure string transforms and
    # run inline; LLM-backed ones cost an API call per prompt, so every such call
    # across every plugin goes into one pool instead of three nested serial loops.
    plan: list[tuple] = []      # (plugin, base_cases, file_strat, slots)
    llm_units: list[tuple] = []  # (plugin_i, slot_i, case_i, case, strategy)
    # Cached cases the config no longer wants. Counted rather than silently
    # discarded: a smaller run than the file implies should be stated.
    dropped_strategies: dict[str, int] = {}
    dropped_orphans: dict[str, int] = {}

    for p_i, (plugin, base_cases) in enumerate(all_plugin_results):
        # Use per-plugin strategies if defined, otherwise fall back to global strategies
        plugin_strategies = plugin.strategies if hasattr(plugin, 'strategies') and plugin.strategies else cfg.strategies

        # A cached variant is kept only when the config still asks for it, and
        # only while the base prompt it was built from survived the num_tests
        # trim. Without the first test a strategy removed from the config kept
        # running off the file; without the second, trimming the base set left
        # variants of prompts that are no longer in the run.
        configured = {s.id for s in plugin_strategies}
        kept_base = {tc.prompt for tc in base_cases}
        file_strat = []
        # Coverage is per prompt: a strategy cached for six prompts still has to
        # be applied to a seventh that the top-up added.
        covered: dict[str, set] = {}
        unlinked: set = set()   # strategies with variants that cannot be aligned
        seen_variants: set = set()
        for tc in file_cases.get(plugin.id, []):
            sid = tc.metadata.get("strategy")
            if not sid:
                continue
            if sid not in configured:
                dropped_strategies[sid] = dropped_strategies.get(sid, 0) + 1
                continue
            # A hand-written or pre-1.0 file may carry no seed link. It cannot be
            # aligned, so it is kept rather than thrown away on a guess.
            origin = tc.metadata.get("original_prompt")
            if origin is not None and origin not in kept_base:
                dropped_orphans[plugin.id] = dropped_orphans.get(plugin.id, 0) + 1
                continue
            # The same variant saved twice is one variant.
            dup_key = (sid, _prompt_key(origin) if origin is not None else _prompt_key(tc.prompt))
            if dup_key in seen_variants:
                continue
            seen_variants.add(dup_key)
            file_strat.append(tc)
            if origin is None:
                unlinked.add(sid)
            else:
                covered.setdefault(sid, set()).add(origin)

        # The amplifier wraps each framing rather than running beside it; the
        # slot count is unchanged either way. Same planner as run.py, so the two
        # runners cannot disagree about what a strategy list expands to.
        amplifier, to_apply = plan_composition(
            plugin_strategies, compose=cfg.compose_strategies
        )

        # A cached variant is replayed exactly as saved — the prompts file is a
        # cache of literal prompts, so a strategy present in the file is a hit
        # whether or not it was amplified when it was written. Composition
        # applies to prompts being built, never to prompts being replayed.
        slots: list[list] = []
        for strat in to_apply:
            if strat.id in unlinked:
                continue
            have = covered.get(strat.id, set())
            todo = [case for case in base_cases if case.prompt not in have]
            if not todo:
                continue
            s_i = len(slots)
            if strat.uses_llm:
                slots.append([None] * len(todo))
                llm_units.extend(
                    (p_i, s_i, c_i, case, strat, amplifier)
                    for c_i, case in enumerate(todo)
                )
            else:
                slots.append(strat.apply_to_cases(
                    todo, generator=cfg.generation, amplifier=amplifier))
        plan.append((plugin, base_cases, file_strat, slots))

    if dropped_strategies:
        detail = ", ".join(f"{sid} ({n})" for sid, n in sorted(dropped_strategies.items()))
        print(f"Dropped {sum(dropped_strategies.values())} cached case(s) for "
              f"strategies this config does not ask for: {detail}")
    if dropped_orphans:
        detail = ", ".join(f"{pid} ({n})" for pid, n in sorted(dropped_orphans.items()))
        print(f"Dropped {sum(dropped_orphans.values())} cached variant(s) whose "
              f"base prompt fell outside num_tests: {detail}")

    if llm_units:
        n_units = len(llm_units)
        strat_conc = max(cfg.concurrency, 1)
        print(f"Applying LLM strategies: {n_units} prompt(s), concurrency={strat_conc}")
        t0 = time.perf_counter()
        failed = 0
        with ThreadPoolExecutor(max_workers=strat_conc) as pool:
            futures = {
                pool.submit(_strategy_variant, case, strat, cfg.generation, amp): (p_i, s_i, c_i)
                for p_i, s_i, c_i, case, strat, amp in llm_units
            }
            for done_n, future in enumerate(as_completed(futures), 1):
                p_i, s_i, c_i = futures[future]
                try:
                    plan[p_i][3][s_i][c_i] = future.result()
                except Exception as exc:
                    failed += 1
                    if failed == 1:
                        print(f"  strategy variant failed (dropped): {exc}", flush=True)
                if done_n % 25 == 0 or done_n == n_units:
                    print(f"  {done_n}/{n_units} variants", flush=True)
        note = f", {failed} dropped" if failed else ""
        print(f"[timing] strategies: {time.perf_counter() - t0:.1f}s{note}\n", flush=True)

    for plugin, base_cases, file_strat, slots in plan:
        # Drop any variant whose LLM call failed rather than duplicating the base prompt.
        variants = [tc for slot in slots for tc in slot if tc is not None]
        final_cases = list(base_cases) + variants + file_strat
        final_batches.append((plugin, base_cases, final_cases))
        all_save_cases.extend(final_cases)

    # Interactive strategies need the target, so they are driven at evaluation
    # time. Collect the configured instances (global + per-plugin) by id.
    interactive_strategies: dict[str, object] = {
        s.id: s
        for s in [
            *cfg.strategies,
            *(s for p in cfg.plugins for s in (getattr(p, "strategies", None) or [])),
        ]
        if s.interactive
    }
    if interactive_strategies:
        for sid, s in interactive_strategies.items():
            print(f"Adaptive strategy '{sid}' enabled "
                  f"(up to {getattr(s, 'max_turns', '?')} turns per case)")

    global_amp, _ = plan_composition(
        cfg.strategies, compose=cfg.compose_strategies
    )
    if global_amp is not None and cfg.strategies:
        print(f"Composing '{global_amp.id}' as an outer layer over every other "
              f"strategy (same case count; set compose_strategies: false to disable)")

    # --- save prompts file (before hitting the target) -----------------------
    if save_prompts_path:
        save_path = _save_prompts(
            Path(save_prompts_path), cfg.purpose,
            [s.id for s in cfg.strategies], all_save_cases,
        )
        print(f"Prompts  → {save_path}")

    # --- generate-only: stop here, no target is hit --------------------------
    if args.generate_only:
        n_convo = sum(
            1 for tc in all_save_cases
            if (tc.metadata.get("strategy") or "") in interactive_strategies
        )
        convo_note = (
            f" ({n_convo} conversational seed(s) — turns are built at run time on --load-prompts)"
            if n_convo else ""
        )
        print(f"\nGenerate-only complete: {len(all_save_cases)} prompt(s) saved{convo_note}.")
        print(f"Reuse with:  knox-rt --config <cfg> --load-prompts {save_path}")
        return

    # --- attack + grade -------------------------------------------------------
    all_records: list[dict] = []
    total = 0
    vulnerable = 0
    by_plugin: dict[str, dict] = {}

    async def _evaluate_case(unit, sem):
        """Attack the target with one case, grade the reply, build its record.

        Returns the record plus the two latencies that matter for tuning: time
        spent in the target and time spent in the grader.
        """
        seq, plugin_id, case, tgt = unit
        strategy  = case.metadata.get("strategy")
        sev_tag   = f"[{case.severity.upper()}] " if case.severity else ""
        strat_tag = f"[{strategy}] " if strategy else ""

        async with sem:
            try:
                return await _evaluate_case_inner(
                    seq, plugin_id, case, tgt, strategy, sev_tag, strat_tag)
            except Exception as exc:
                # A dropped case used to vanish from the results entirely. Record
                # it instead — a security tool must not silently hide failures.
                cat_key, cat_label = category_for_plugin(case.plugin_id, case.detector_id)
                err = f"{type(exc).__name__}: {exc}"
                return {
                    "seq": seq, "plugin_id": plugin_id, "target": tgt.name,
                    "verdict": "ERROR     ", "sev_tag": sev_tag, "strat_tag": strat_tag,
                    "passed": None, "severity": case.severity,
                    "t_target": 0.0, "t_grade": 0.0, "error": err,
                    "record": {
                        "run_id": run_id, "timestamp": _now(), "target": tgt.name,
                        "plugin_id": case.plugin_id, "detector_id": case.detector_id,
                        "category": cat_key, "category_label": cat_label,
                        "strategy": strategy, "attack": case.prompt,
                        "severity": PLUGIN_SEVERITY.get(case.plugin_id) or PLUGIN_SEVERITY.get(case.detector_id) or None,
                        "user_specified_severity": case.metadata.get("user_specified_severity"),
                        "frameworks": case.frameworks or None,
                        "controls": case.controls or None,
                        "response": None, "passed": None, "score": None,
                        "reason": None, "error": err,
                        "purpose": cfg.purpose,
                        "generation_model": cfg.generation.name if cfg.generation else None,
                        "grading_model": cfg.grading.name,
                    },
                }

    async def _evaluate_case_inner(seq, plugin_id, case, tgt, strategy, sev_tag, strat_tag):
        if True:
            loop = asyncio.get_event_loop()

            # Prefer the plugin's dedicated grader, whose `violation` is written in
            # response voice ("reveals its system prompt"). CustomDetector reuses the
            # generation objective as the rubric instead — correct for user-defined
            # plugins (detector_id "custom"), but attacker-voiced objectives like
            # "replace the operator's system prompt" describe the attack rather than
            # the response, so a built-in must never fall through to it.
            obj = case.metadata.get("objective")
            if case.detector_id in _DETECTOR_IDS and case.detector_id != "custom":
                detector = get_detector(case.detector_id, cfg.grading)
            elif obj:
                from detectors.custom import CustomDetector
                detector = CustomDetector(cfg.grading, objective=obj)
            else:
                detector = get_detector(case.detector_id, cfg.grading)

            interactive = interactive_strategies.get(case.metadata.get("strategy") or "")
            turns, transcript, backtracks, reconfirmed = 1, None, None, None
            # The attack's goal, given to the judge on every grading call so a
            # drifting turn or a strategy wrapper is judged against what the
            # attack is actually for, not just the literal final message.
            objective = objective_for(case.plugin_id, case.detector_id, case.metadata)

            if interactive is not None:
                # Multi-turn: the strategy owns the loop, grading each turn to
                # decide whether to refine. One executor slot for the whole
                # conversation; concurrency still comes from the semaphore.
                t0 = time.perf_counter()
                convo = await loop.run_in_executor(
                    None,
                    lambda: interactive.run_conversation(
                        seed_prompt=case.prompt,
                        target=tgt,
                        grade=lambda a, r: detector.grade(
                            attack=a, response=r, purpose=cfg.purpose,
                            objective=objective),
                        generator=cfg.generation,
                        purpose=cfg.purpose,
                        objective=objective,
                        # Already resolved (per-plugin over global) when the
                        # plugin built the case, so refined turns inherit the
                        # same contract the seed prompt was generated under.
                        language=case.metadata.get("language") or "",
                        max_chars=case.metadata.get("max_chars") or 0,
                        instructions=turn_instructions(
                            case.detector_id,
                            case.metadata.get("generation_instructions") or ""),
                        examples=case.metadata.get("examples") or "",
                        proof_probe=(INJECTION_PROOF_PROBE
                                     if case.detector_id in INJECTION_FAMILY_IDS else ""),
                    ),
                )
                elapsed = time.perf_counter() - t0
                attack_prompt = convo["attack"]
                response = convo["response"]
                result = convo["result"]
                turns = convo["turns"]
                transcript = convo["transcript"]
                backtracks = convo.get("backtracks")
                reconfirmed = convo.get("reconfirmed")
                # Target and grading interleave inside the loop, so split the
                # measured time evenly rather than reporting a fake breakdown.
                t_target = t_grade = elapsed / 2
            else:
                attack_prompt = case.prompt

                t0 = time.perf_counter()
                response = await loop.run_in_executor(None, tgt.generate, case.prompt)
                t_target = time.perf_counter() - t0

                if cfg.delay_ms:
                    await asyncio.sleep(cfg.delay_ms / 1000)

                t1 = time.perf_counter()
                result = await loop.run_in_executor(
                    None,
                    lambda: detector.grade(
                        attack=case.prompt, response=response, purpose=cfg.purpose,
                        objective=objective, original=encoded_original(case)),
                )
                t_grade = time.perf_counter() - t1

            cat_key, cat_label = category_for_plugin(case.plugin_id, case.detector_id)

            record = {
                "run_id": run_id,
                "timestamp": _now(),
                "target": tgt.name,
                "plugin_id": case.plugin_id,
                "detector_id": case.detector_id,
                "category": cat_key,
                "category_label": cat_label,
                "objective": objective or None,
                "frameworks": case.frameworks or None,
                "controls": case.controls or None,
                # `severity` is always our built-in default for the attack type;
                # `user_specified_severity` carries the user's per-plugin/global
                # override when they set one, else null.
                "severity": PLUGIN_SEVERITY.get(case.plugin_id) or PLUGIN_SEVERITY.get(case.detector_id) or None,
                "user_specified_severity": case.metadata.get("user_specified_severity"),
                "strategy": strategy,
                # For a multi-turn case this is the attack that actually landed,
                # which may be several refinements past the seed prompt.
                "attack": attack_prompt,
                "original_prompt": case.metadata.get("original_prompt") or (
                    case.prompt if interactive is not None else None),
                "turns": turns,
                "transcript": transcript,
                "backtracks": backtracks,
                "reconfirmed": reconfirmed,
                "response": response,
                "passed": result.passed,
                "score": result.score,
                "reason": result.reason,
                # The evidence the verdict was derived from: the judge's quote,
                # whether code found it in the response, and the delivered level.
                # None when no quote check ran (empty response, legacy-format
                # reply), which is itself the signal to distrust a finding.
                "axes": getattr(result, "axes", None),
                "purpose": cfg.purpose,
                "generation_model": cfg.generation.name if cfg.generation else None,
                "grading_model": cfg.grading.name,
                "language": case.metadata.get("language"),
                "language_code": case.metadata.get("language_code"),
                "max_chars": case.metadata.get("max_chars"),
                "num_tests": case.metadata.get("num_tests"),
                "generation_instructions": case.metadata.get("generation_instructions"),
                "examples": case.metadata.get("examples"),
            }
            return {
                "seq":       seq,
                "plugin_id": plugin_id,
                "target":    tgt.name,
                # None = the judge returned no readable verdict. It shares the
                # ERROR lane with transport failures: counted by neither side.
                "verdict":   ("ERROR     " if result.passed is None
                              else "RESISTED " if result.passed
                              else "VULNERABLE"),
                "sev_tag":   sev_tag,
                "strat_tag": strat_tag,
                "passed":    result.passed,
                "severity":  case.severity,
                "record":    record,
                "t_target":  t_target,
                "t_grade":   t_grade,
            }

    def _err_suffix(res):
        err = res.get("error")
        return f"  ({' '.join(str(err).split())[:200]})" if err else ""

    async def _evaluate_all(units, concurrency):
        """Run every case from every plugin in one pool.

        Evaluating per-plugin would cap in-flight requests at that plugin's case
        count and stall on its slowest case before the next plugin starts.
        """
        # Provider and judge calls are blocking, so they run in a thread pool.
        # The default executor is capped at min(32, cpu_count + 4) — on most
        # machines below a high --concurrency, which would silently throttle the
        # semaphore. Size the pool to the concurrency actually requested.
        loop = asyncio.get_event_loop()
        pool = ThreadPoolExecutor(max_workers=concurrency,
                                  thread_name_prefix="knox-eval")
        loop.set_default_executor(pool)

        sem = asyncio.Semaphore(concurrency)
        tasks = [asyncio.create_task(_evaluate_case(u, sem)) for u in units]

        done_n, n_total, out = 0, len(units), []
        for fut in asyncio.as_completed(tasks):
            done_n += 1
            try:
                res = await fut
            except Exception as exc:
                print(f"  [{done_n}/{n_total}] ERROR: {exc}", flush=True)
                continue
            tgt_col = f"{res['target']:<18} " if is_multi else ""
            print(f"  [{done_n}/{n_total}] {res['plugin_id']:<34} "
                  f"{res['sev_tag']}{res['strat_tag']}{tgt_col}{res['verdict']}"
                  f"{_err_suffix(res)}", flush=True)
            out.append(res)
        pool.shutdown(wait=False)
        return out

    # One flat pool across all plugins and targets, so `concurrency` is the only
    # thing bounding how many requests are in flight.
    units = [
        (seq, plugin.id, case, tgt)
        for seq, (plugin, case, tgt) in enumerate(
            (plugin, case, tgt)
            for plugin, _, final_cases in final_batches
            for case in final_cases
            for tgt in cfg.targets
        )
    ]
    for plugin, _, _ in final_batches:
        by_plugin[plugin.id] = {"total": 0, "vulnerable": 0}

    eval_concurrency = cfg.concurrency if cfg.concurrency and cfg.concurrency > 1 else 4

    # The [0/N] gives the UI its denominator up front, so the bar reads 0/N
    # instead of 0/1 until the first case lands.
    print(f"Evaluating {len(units)} case(s) from {len(final_batches)} plugin(s), "
          f"concurrency={eval_concurrency}  [0/{len(units)}]\n", flush=True)

    eval_start = time.perf_counter()
    results = asyncio.run(_evaluate_all(units, eval_concurrency))
    eval_elapsed = time.perf_counter() - eval_start

    # Display streams in completion order; records are re-sorted so the output
    # file does not depend on which case happened to finish first.
    errored = 0
    for res in sorted(results, key=lambda r: r["seq"]):
        all_records.append(res["record"])
        total += 1
        by_plugin[res["plugin_id"]]["total"] += 1
        by_plugin[res["plugin_id"]].setdefault("severity", res["severity"] or "")
        # passed is None for an errored case — neither a break nor a resist, so it
        # must not be miscounted as vulnerable (not None == True).
        if res["passed"] is None:
            errored += 1
            by_plugin[res["plugin_id"]]["errored"] = by_plugin[res["plugin_id"]].get("errored", 0) + 1
        elif not res["passed"]:
            vulnerable += 1
            by_plugin[res["plugin_id"]]["vulnerable"] += 1

    if results:
        t_target_sum = sum(r["t_target"] for r in results)
        t_grade_sum  = sum(r["t_grade"] for r in results)
        n = len(results)
        serial = t_target_sum + t_grade_sum
        print(f"\n[timing] evaluation: {eval_elapsed:.1f}s wall for {n} case(s)")
        print(f"[timing]   target : {t_target_sum / n:.2f}s avg/case  "
              f"({t_target_sum:.1f}s total)")
        print(f"[timing]   grading: {t_grade_sum / n:.2f}s avg/case  "
              f"({t_grade_sum:.1f}s total)")
        print(f"[timing]   effective parallelism: {serial / eval_elapsed:.1f}x "
              f"of {eval_concurrency} configured")
    print()

    # --- summary --------------------------------------------------------------
    # An errored case is neither a pass nor a fail: keep it out of `vulnerable`
    # and out of the pass-rate denominator (rate is over *decided* cases only).
    def _pass_rate(counts: dict) -> float:
        decided = counts["total"] - counts.get("errored", 0)
        return round((decided - counts["vulnerable"]) / decided, 3) if decided else 0.0

    for counts in by_plugin.values():
        counts["pass_rate"] = _pass_rate(counts)

    by_framework: dict[str, dict] = {}
    for rec in all_records:
        for fw in (rec.get("frameworks") or []):
            bucket = by_framework.setdefault(fw, {"total": 0, "vulnerable": 0, "errored": 0})
            bucket["total"] += 1
            if rec.get("passed") is None:
                bucket["errored"] += 1
            elif not rec["passed"]:
                bucket["vulnerable"] += 1
    for counts in by_framework.values():
        counts["pass_rate"] = _pass_rate(counts)

    # by_strategy — attack success rate per strategy, against the unmodified
    # baseline. Every other breakdown answers "how exposed is the target";
    # this one answers "is our attack tooling any good", which is the only way
    # to tell a hardened target from a strategy that stopped working. Baseline
    # cases carry no strategy and bucket under "none" so the comparison — the
    # lift a strategy buys over sending the raw prompt — is on the same table.
    by_strategy: dict[str, dict] = {}
    for rec in all_records:
        bucket = by_strategy.setdefault(
            rec.get("strategy") or "none",
            {"total": 0, "vulnerable": 0, "errored": 0},
        )
        bucket["total"] += 1
        if rec.get("passed") is None:
            bucket["errored"] += 1
        elif not rec["passed"]:
            bucket["vulnerable"] += 1
    for counts in by_strategy.values():
        counts["pass_rate"] = _pass_rate(counts)
        # The headline number, stored explicitly rather than left as
        # 1 - pass_rate: an errored case is in neither, and a reader doing that
        # subtraction by hand gets it wrong whenever any case errored.
        decided_n = counts["total"] - counts["errored"]
        counts["attack_success_rate"] = (
            round(counts["vulnerable"] / decided_n, 3) if decided_n else 0.0
        )

    # by_target — per-target pass/fail breakdown (most useful in multi-target runs)
    by_target: dict[str, dict] = {}
    for rec in all_records:
        tgt_name = rec.get("target", "default")
        bucket = by_target.setdefault(tgt_name, {"total": 0, "vulnerable": 0, "errored": 0})
        bucket["total"] += 1
        if rec.get("passed") is None:
            bucket["errored"] += 1
        elif not rec["passed"]:
            bucket["vulnerable"] += 1
    for counts in by_target.values():
        counts["pass_rate"] = _pass_rate(counts)

    decided = total - errored
    summary = {
        "run_id":       run_id,
        "timestamp":    _now(),
        "total":        total,
        "vulnerable":   vulnerable,
        "resisted":     decided - vulnerable,
        "errored":      errored,
        "pass_rate":    round((decided - vulnerable) / decided, 3) if decided else 0.0,
        "by_plugin":    by_plugin,
        "by_framework": by_framework or None,
        "by_strategy":  by_strategy or None,
        "by_target":    by_target if is_multi else None,
    }

    # --- write output ---------------------------------------------------------
    with out_file.open("w", encoding="utf-8") as f:
        if fmt == "json":
            json.dump({"summary": summary, "results": all_records}, f, indent=2)
            f.write("\n")
        else:
            for rec in all_records:
                f.write(json.dumps(rec) + "\n")
            f.write(json.dumps({**summary, "type": "summary"}) + "\n")

    # --- print summary --------------------------------------------------------
    print("=" * 50)
    print(f"Total      : {total}")
    print(f"Vulnerable : {vulnerable}  ({vulnerable / decided:.0%})" if decided else "Vulnerable : 0")
    print(f"Resisted   : {decided - vulnerable}  ({summary['pass_rate']:.0%})" if decided else "Resisted   : 0")
    if errored:
        print(f"Errored    : {errored}  (excluded from rates — see 'error' field in results)")
    print("\nBy plugin:")
    for pid, counts in by_plugin.items():
        sev = counts.get("severity", "")
        sev_label = f"[{sev.upper()}] " if sev else ""
        bar = "█" * counts["vulnerable"] + "░" * (counts["total"] - counts["vulnerable"])
        print(f"  {sev_label}{pid:<30} {bar}  {counts['vulnerable']}/{counts['total']} vulnerable")

    # Severity breakdown — only shown when at least one plugin has severity set.
    severity_order = ["critical", "high", "medium", "low"]
    by_sev: dict[str, dict] = {}
    for counts in by_plugin.values():
        sev = counts.get("severity", "")
        if sev:
            bucket = by_sev.setdefault(sev, {"total": 0, "vulnerable": 0})
            bucket["total"]     += counts["total"]
            bucket["vulnerable"] += counts["vulnerable"]
    if by_sev:
        print("\nBy severity:")
        for sev in severity_order:
            if sev in by_sev:
                b = by_sev[sev]
                print(f"  {sev:<10}  {b['vulnerable']}/{b['total']} vulnerable")

    if by_framework:
        print("\nBy framework:")
        for fw, b in by_framework.items():
            print(f"  {fw:<20}  {b['vulnerable']}/{b['total']} vulnerable")

    # Only worth printing when a strategy actually ran: with no strategies the
    # single "none" row just restates the totals above.
    if len(by_strategy) > 1:
        print("\nBy strategy (attack success rate):")
        baseline = by_strategy.get("none")
        col = max(len(s) for s in by_strategy) + 2
        # Baseline first, then the rest strongest-first — the ordering a reader
        # wants when deciding which strategies are earning their API calls.
        ordered = sorted(
            by_strategy.items(),
            key=lambda kv: (kv[0] != "none", -kv[1]["attack_success_rate"]),
        )
        for sid, b in ordered:
            decided_n = b["total"] - b["errored"]
            lift = ""
            if baseline is not None and sid != "none":
                delta = b["attack_success_rate"] - baseline["attack_success_rate"]
                lift = f"   {delta:+.0%} vs baseline"
            err = f"  ({b['errored']} errored)" if b["errored"] else ""
            print(f"  {sid:<{col}} {b['attack_success_rate']:>5.0%}  "
                  f"({b['vulnerable']}/{decided_n}){err}{lift}")
        # A rate over a handful of cases is mostly sampling noise, and a strategy
        # comparison invites exactly that misreading — so say it rather than
        # letting two single-digit numbers look like a result.
        if min(b["total"] - b["errored"] for b in by_strategy.values()) < 20:
            print("  note: fewer than 20 decided cases in some buckets — these "
                  "rates carry wide error bars; raise --num-tests to compare.")

    if is_multi:
        print("\nBy target (comparison):")
        col = max(len(n) for n in by_target) + 2
        for tgt_name, b in by_target.items():
            bar = "█" * b["vulnerable"] + "░" * (b["total"] - b["vulnerable"])
            print(f"  {tgt_name:<{col}} {bar}  {b['vulnerable']}/{b['total']} vulnerable  ({b['pass_rate']:.0%} resisted)")

    print(f"\nResults → {out_file}")


if __name__ == "__main__":
    main()
