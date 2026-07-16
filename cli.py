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
from plugins import CATEGORIES, all_plugin_ids, get_plugin, resolve_plugin_ids
from strategies import _REGISTRY as _STRATEGY_REGISTRY, apply_strategies, get_strategy


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
            "target identifier — meaning depends on --target-type:  "
            "rest→base URL (http://my-api:8080),  "
            "openai→model name (gpt-4o),  "
            "function→module#fn (test_func#check_api_key)"
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
    no_llm = ["base64", "rot13", "leetspeak",
               "fiction", "citation", "refusal-suppression", "manyshot", "crescendo"]
    llm_based = ["jailbreak", "multilingual"]

    print("knox-rt — available strategies\n" + "=" * 50)
    print("\nNo-LLM  (fast, no extra API calls):")
    for sid in no_llm:
        print(f"  - {sid}")
    print("\nLLM-based  (use the generation model, extra API calls):")
    for sid in llm_based:
        print(f"  - {sid}")
    print("\nWith config options (use config.yaml for full control):")
    print("  multilingual  — language: zh | es | fr | de | ar | ru | ja | pt | ko | hi")
    print("  manyshot      — num_shots: N  (default: 8)")


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
    header: dict = {}
    cases: list = []
    for i, raw in enumerate(path.read_text(encoding="utf-8").splitlines()):
        raw = raw.strip()
        if not raw:
            continue
        obj = json.loads(raw)
        if i == 0 and "_knox_rt_version" in obj:
            header = obj
        else:
            cases.append(_dict_to_tc(obj))
    return header, cases


def _save_prompts(path: Path, purpose: str, strategy_ids: list[str], cases: list) -> None:
    header = {
        "_knox_rt_version": "1.0",
        "_generated_at":    _now(),
        "_purpose":         purpose,
        "_strategies":      strategy_ids,
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(json.dumps(header) + "\n")
        for tc in cases:
            f.write(json.dumps(_tc_to_dict(tc)) + "\n")
    tmp.rename(path)


def _run_plugin_with_topup(plugin, file_base: list) -> tuple:
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
    return plugin, file_base + new_cases


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
    all_plugin_results: list[tuple] = []
    if cfg.concurrency <= 1:
        for plugin in cfg.plugins:
            file_base = [tc for tc in file_cases.get(plugin.id, [])
                         if not tc.metadata.get("strategy")]
            all_plugin_results.append(_run_plugin_with_topup(plugin, file_base))
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
                all_plugin_results.append(future.result())

    # --- build final case lists (apply only strategies missing from file) -----
    # For each plugin:
    #   file_strat  = strategy variants already saved in the file
    #   done        = strategy ids already represented in the file
    #   missing     = config strategies not yet in the file → apply fresh
    #   final_cases = base + file_strat + newly applied variants  (union)
    all_save_cases: list = []
    final_batches: list[tuple] = []   # (plugin, base_cases, final_cases)

    for plugin, base_cases in all_plugin_results:
        file_strat = [tc for tc in file_cases.get(plugin.id, [])
                      if tc.metadata.get("strategy")]
        done = {tc.metadata["strategy"] for tc in file_strat}
        missing = [s for s in cfg.strategies if s.id not in done]
        # apply_strategies returns originals + augmented; use it as the full list.
        all_strat = apply_strategies(base_cases, missing, cfg.generation) if missing else base_cases
        final_cases = all_strat + file_strat
        final_batches.append((plugin, base_cases, final_cases))
        all_save_cases.extend(final_cases)

    # --- save prompts file (before hitting the target) -----------------------
    if save_prompts_path:
        save_path = Path(save_prompts_path)
        _save_prompts(save_path, cfg.purpose, [s.id for s in cfg.strategies], all_save_cases)
        print(f"Prompts  → {save_path}")

    # --- attack + grade -------------------------------------------------------
    all_records: list[dict] = []
    total = 0
    vulnerable = 0
    by_plugin: dict[str, dict] = {}

    for plugin, base_cases, final_cases in final_batches:
        n_strat = len(final_cases) - len(base_cases)
        strategy_note = f", {n_strat} strategy-augmented" if n_strat else ""
        augmented = final_cases
        print(f"=== {plugin.id} ===")
        print(f"{len(base_cases)} base attack(s){strategy_note} → {len(final_cases)} total\n")

        by_plugin[plugin.id] = {"total": 0, "vulnerable": 0}

        for i, case in enumerate(augmented, 1):
            strategy = case.metadata.get("strategy")
            sev_tag   = f"[{case.severity.upper()}] " if case.severity else ""
            strat_tag = f"[{strategy}] " if strategy else ""
            print(f"  [{i}] {sev_tag}{strat_tag}{case.prompt}")

            # Run against every target (single loop when not multi-target)
            for tgt in cfg.targets:
                response = tgt.generate(case.prompt)
                if cfg.delay_ms:
                    time.sleep(cfg.delay_ms / 1000)
                obj = case.metadata.get("objective")
                if obj:
                    from detectors.custom import CustomDetector
                    detector = CustomDetector(cfg.grading, objective=obj)
                else:
                    detector = get_detector(case.detector_id, cfg.grading)
                result = detector.grade(
                    attack=case.prompt, response=response, purpose=cfg.purpose
                )

                verdict = "RESISTED " if result.passed else "VULNERABLE"
                if is_multi:
                    print(f"       {tgt.name:<25} → {verdict}  {result.reason}")
                else:
                    print(f"       {verdict}  {result.reason}")

                all_records.append({
                    "run_id":           run_id,
                    "timestamp":        _now(),
                    "target":           tgt.name,
                    "plugin_id":        case.plugin_id,
                    "detector_id":      case.detector_id,
                    "objective":        case.metadata.get("objective") or None,
                    "frameworks":       case.frameworks or None,
                    "controls":         case.controls or None,
                    "severity":         case.severity or None,
                    "strategy":         strategy,
                    "attack":           case.prompt,
                    "original_prompt":  case.metadata.get("original_prompt"),
                    "response":         response,
                    "passed":           result.passed,
                    "score":            result.score,
                    "reason":           result.reason,
                    "purpose":          cfg.purpose,
                    "generation_model": cfg.generation.name,
                    "grading_model":    cfg.grading.name,
                })

                total += 1
                by_plugin[plugin.id]["total"] += 1
                by_plugin[plugin.id].setdefault("severity", case.severity or "")
                if not result.passed:
                    vulnerable += 1
                    by_plugin[plugin.id]["vulnerable"] += 1

            if is_multi:
                print()   # blank line between attacks in multi-target mode

        print()

    # --- summary --------------------------------------------------------------
    for counts in by_plugin.values():
        t = counts["total"]
        counts["pass_rate"] = round((t - counts["vulnerable"]) / t, 3) if t else 0.0

    by_framework: dict[str, dict] = {}
    for rec in all_records:
        for fw in (rec.get("frameworks") or []):
            bucket = by_framework.setdefault(fw, {"total": 0, "vulnerable": 0})
            bucket["total"] += 1
            if not rec["passed"]:
                bucket["vulnerable"] += 1
    for counts in by_framework.values():
        t = counts["total"]
        counts["pass_rate"] = round((t - counts["vulnerable"]) / t, 3) if t else 0.0

    # by_target — per-target pass/fail breakdown (most useful in multi-target runs)
    by_target: dict[str, dict] = {}
    for rec in all_records:
        tgt_name = rec.get("target", "default")
        bucket = by_target.setdefault(tgt_name, {"total": 0, "vulnerable": 0})
        bucket["total"] += 1
        if not rec["passed"]:
            bucket["vulnerable"] += 1
    for counts in by_target.values():
        t = counts["total"]
        counts["pass_rate"] = round((t - counts["vulnerable"]) / t, 3) if t else 0.0

    summary = {
        "run_id":       run_id,
        "timestamp":    _now(),
        "total":        total,
        "vulnerable":   vulnerable,
        "resisted":     total - vulnerable,
        "pass_rate":    round((total - vulnerable) / total, 3) if total else 0.0,
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
    print(f"Vulnerable : {vulnerable}  ({vulnerable / total:.0%})" if total else "Vulnerable : 0")
    print(f"Resisted   : {total - vulnerable}  ({summary['pass_rate']:.0%})" if total else "Resisted   : 0")
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
