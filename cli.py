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
from detectors import get_detector
from inference import CallableProvider, RestProvider
from plugins import CATEGORIES, _REGISTRY, all_plugin_ids, category_for_plugin, get_plugin, resolve_plugin_ids
from strategies import _REGISTRY as _STRATEGY_REGISTRY, get_strategy


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
        help="parallel worker threads (overrides config)",
    )

    tgt = p.add_argument_group("target (system under test)")
    tgt.add_argument(
        "--target-type", "-t", default=None,
        choices=["rest", "openai", "function"],
        metavar="TYPE",
        help="target backend type: rest | openai | function",
    )
    tgt.add_argument(
        "--target-name", default=None, metavar="NAME",
        help=(
            "target identifier - meaning depends on --target-type:  "
            "rest: base URL (http://my-api:8080),  "
            "openai: model name (gpt-4o),  "
            "function: module#fn (my_module#invoke)"
        ),
    )
    tgt.add_argument(
        "--target-model", default=None, metavar="MODEL",
        help="model name sent in the REST request body (rest type only)",
    )
    tgt.add_argument(
        "--target-api-key", default=None, metavar="KEY",
        help="Bearer token for the target (rest / openai types)",
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
        help="save generated prompts (post-strategy) to a JSONL file for reuse across runs",
    )
    cache.add_argument(
        "--load-prompts", default=None, metavar="PATH",
        help="load prompts from a saved JSONL file; skips generation for cached plugins/strategies, tops up missing ones",
    )

    return p


# --------------------------------------------------------------------------- #
# Discovery commands
# --------------------------------------------------------------------------- #

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


def _run_plugin_with_topup(plugin, file_base: list) -> tuple:
    t0 = time.perf_counter()
    shortfall = max(0, plugin.num_tests - len(file_base))
    if shortfall > 0:
        orig = plugin.num_tests
        plugin.num_tests = shortfall
        try:
            new_cases = plugin.generate_tests()
        finally:
            plugin.num_tests = orig
    else:
        new_cases = []
    return plugin, file_base + new_cases, round(time.perf_counter() - t0, 2)


def _strategy_variant(case, strategy, generator):
    """One strategy variant of one case — the unit of work for the pool.

    Delegates to apply_to_cases so TestCase bookkeeping stays in one place.
    """
    return strategy.apply_to_cases([case], generator=generator)[0]


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
    cfg = load_config(args.config) if args.config else load_config()

    if args.purpose:
        cfg.purpose = args.purpose
    if args.num_tests:
        cfg.num_tests = args.num_tests
    if args.concurrency:
        cfg.concurrency = args.concurrency

    if args.plugins:
        entries = [e.strip() for e in args.plugins.split(",")]
        plugin_ids = resolve_plugin_ids(entries)
        cfg.plugins = [
            get_plugin(pid, cfg.generation, cfg.purpose,
                       num_tests=cfg.num_tests, concurrency=cfg.concurrency)
            for pid in plugin_ids
        ]

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
    elif cfg.targets:
        target = cfg.targets[0]   # single-target path — use first (and only) target
    else:
        parser.error(
            "no target configured — use --target-type rest|openai|function "
            "or add a 'target: type:' / 'targets:' block to config.yaml"
        )

    # Normalise: CLI flags set cfg.target but not cfg.targets — unify here.
    if not cfg.targets and target:
        cfg.targets = [target]

    is_multi = len(cfg.targets) > 1

    # CLI flag takes priority over config file value for both prompts flags.
    save_prompts_path = args.save_prompts or cfg.save_prompts
    load_prompts_path = args.load_prompts or cfg.load_prompts

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
    print(f"Output          : {out_file}  [{fmt.upper()}]")
    if is_multi:
        print(f"Targets         : {', '.join(t.name for t in cfg.targets)}")
    else:
        print(f"Target          : {target.name}")
    print(f"Target purpose  : {cfg.purpose}")
    print(f"Generation model: {cfg.generation.name}")
    print(f"Grading model   : {cfg.grading.name}")
    print(f"Tests/plugin      : {cfg.num_tests}")
    print(f"Concurrency     : {cfg.concurrency}")
    if cfg.strategies:
        print(f"Strategies      : {', '.join(s.id for s in cfg.strategies)}")
    if load_prompts_path:
        print(f"Load prompts    : {load_prompts_path}")
    if save_prompts_path:
        print(f"Save prompts    : {save_prompts_path}")
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
            print(f"  {plugin.id:<40} {len(cases)} prompt(s)  [{src}]{strat_info}")
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
                print(f"  {plugin.id:<40} {len(cases)} prompt(s)  [{src}]{strat_info}")
    print(f"\n[timing] generation: {time.perf_counter() - run_start:.1f}s\n")

    # --- build final case lists (apply only strategies missing from file) -----
    # For each plugin:
    #   file_strat  = strategy variants already saved in the file
    #   done        = strategy ids already represented in the file
    #   missing     = config strategies not yet in the file → apply fresh
    #   final_cases = base + file_strat + newly applied variants  (union)
    all_save_cases: list = []
    final_batches: list[tuple] = []   # (plugin, base_cases, final_cases)

    # Plan first, then execute. Non-LLM strategies are pure string transforms and
    # run inline; LLM-backed ones cost an API call per prompt, so every such call
    # across every plugin goes into one pool instead of three nested serial loops.
    plan: list[tuple] = []      # (plugin, base_cases, file_strat, slots)
    llm_units: list[tuple] = []  # (plugin_i, slot_i, case_i, case, strategy)

    for p_i, (plugin, base_cases) in enumerate(all_plugin_results):
        file_strat = [tc for tc in file_cases.get(plugin.id, [])
                      if tc.metadata.get("strategy")]
        done = {tc.metadata["strategy"] for tc in file_strat}

        # Use per-plugin strategies if defined, otherwise fall back to global strategies
        plugin_strategies = plugin.strategies if hasattr(plugin, 'strategies') and plugin.strategies else cfg.strategies

        missing = [s for s in plugin_strategies if s.id not in done]

        slots: list[list] = []
        for s_i, strat in enumerate(missing):
            if strat.uses_llm:
                slots.append([None] * len(base_cases))
                llm_units.extend(
                    (p_i, s_i, c_i, case, strat)
                    for c_i, case in enumerate(base_cases)
                )
            else:
                slots.append(strat.apply_to_cases(base_cases, generator=cfg.generation))
        plan.append((plugin, base_cases, file_strat, slots))

    if llm_units:
        n_units = len(llm_units)
        strat_conc = max(cfg.concurrency, 1)
        print(f"Applying LLM strategies: {n_units} prompt(s), concurrency={strat_conc}")
        t0 = time.perf_counter()
        failed = 0
        with ThreadPoolExecutor(max_workers=strat_conc) as pool:
            futures = {
                pool.submit(_strategy_variant, case, strat, cfg.generation): (p_i, s_i, c_i)
                for p_i, s_i, c_i, case, strat in llm_units
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

    # --- save prompts file (before hitting the target) -----------------------
    if save_prompts_path:
        save_path = _save_prompts(
            Path(save_prompts_path), cfg.purpose,
            [s.id for s in cfg.strategies], all_save_cases,
        )
        print(f"Prompts  → {save_path}")

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
                        "severity": case.severity or None,
                        "frameworks": case.frameworks or None,
                        "controls": case.controls or None,
                        "response": None, "passed": None, "score": None,
                        "reason": None, "error": err,
                        "purpose": cfg.purpose,
                        "generation_model": cfg.generation.name,
                        "grading_model": cfg.grading.name,
                    },
                }

    async def _evaluate_case_inner(seq, plugin_id, case, tgt, strategy, sev_tag, strat_tag):
        if True:
            loop = asyncio.get_event_loop()

            obj = case.metadata.get("objective")
            if obj:
                from detectors.custom import CustomDetector
                detector = CustomDetector(cfg.grading, objective=obj)
            else:
                detector = get_detector(case.detector_id, cfg.grading)

            interactive = interactive_strategies.get(case.metadata.get("strategy") or "")
            turns, transcript, backtracks = 1, None, None

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
                            attack=a, response=r, purpose=cfg.purpose),
                        generator=cfg.generation,
                        purpose=cfg.purpose,
                        objective=case.metadata.get("objective") or "",
                        # Already resolved (per-plugin over global) when the
                        # plugin built the case, so refined turns inherit the
                        # same contract the seed prompt was generated under.
                        language=case.metadata.get("language") or "",
                        max_chars=case.metadata.get("max_chars") or 0,
                        instructions=case.metadata.get("generation_instructions") or "",
                        examples=case.metadata.get("examples") or "",
                    ),
                )
                elapsed = time.perf_counter() - t0
                attack_prompt = convo["attack"]
                response = convo["response"]
                result = convo["result"]
                turns = convo["turns"]
                transcript = convo["transcript"]
                backtracks = convo.get("backtracks")
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
                        attack=case.prompt, response=response, purpose=cfg.purpose),
                )
                t_grade = time.perf_counter() - t1

            cat_key, cat_label = category_for_plugin(case.plugin_id, case.detector_id)
            objective = case.metadata.get("objective") or None
            if not objective:
                cls = _REGISTRY.get(case.plugin_id) or _REGISTRY.get(case.detector_id)
                objective = getattr(cls, "objective", None) or None

            record = {
                "run_id": run_id,
                "timestamp": _now(),
                "target": tgt.name,
                "plugin_id": case.plugin_id,
                "detector_id": case.detector_id,
                "category": cat_key,
                "category_label": cat_label,
                "objective": objective,
                "frameworks": case.frameworks or None,
                "controls": case.controls or None,
                "severity": case.severity or None,
                "strategy": strategy,
                # For a multi-turn case this is the attack that actually landed,
                # which may be several refinements past the seed prompt.
                "attack": attack_prompt,
                "original_prompt": case.metadata.get("original_prompt") or (
                    case.prompt if interactive is not None else None),
                "turns": turns,
                "transcript": transcript,
                "backtracks": backtracks,
                "response": response,
                "passed": result.passed,
                "score": result.score,
                "reason": result.reason,
                "purpose": cfg.purpose,
                "generation_model": cfg.generation.name,
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
                "verdict":   "RESISTED " if result.passed else "VULNERABLE",
                "sev_tag":   sev_tag,
                "strat_tag": strat_tag,
                "passed":    result.passed,
                "severity":  case.severity,
                "record":    record,
                "t_target":  t_target,
                "t_grade":   t_grade,
            }

    async def _evaluate_all(units, concurrency):
        """Run every case from every plugin in one pool.

        Evaluating per-plugin would cap in-flight requests at that plugin's case
        count and stall on its slowest case before the next plugin starts.
        """
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
                  f"{res['sev_tag']}{res['strat_tag']}{tgt_col}{res['verdict']}", flush=True)
            out.append(res)
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

    if is_multi:
        print("\nBy target (comparison):")
        col = max(len(n) for n in by_target) + 2
        for tgt_name, b in by_target.items():
            bar = "█" * b["vulnerable"] + "░" * (b["total"] - b["vulnerable"])
            print(f"  {tgt_name:<{col}} {bar}  {b['vulnerable']}/{b['total']} vulnerable  ({b['pass_rate']:.0%} resisted)")

    print(f"\nResults → {out_file}")


if __name__ == "__main__":
    main()
