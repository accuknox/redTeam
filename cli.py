#!/usr/bin/env python3
"""knox-rt — Knox Red Team CLI.

LLM adversarial testing toolkit by AccuKnox.

Usage
-----
    knox-rt --list-plugins
    knox-rt --list-strategies
    knox-rt --plugins prompt-injection --strategies base64,fiction
    knox-rt --plugins jailbreak,code --num-generations 3 -o run1.json
    knox-rt --config custom.yaml --format jsonl

    # or without installing:
    python cli.py --list-plugins
"""

from __future__ import annotations

import argparse
import json
import sys
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
        help="path to config.yaml (default: config.yaml in cwd)",
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
        "--num-generations", "-n", type=int, default=None, metavar="N",
        help="attacks per plugin (overrides config)",
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


def _run_plugin(plugin):
    return plugin, plugin.generate_tests()


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
    if args.num_generations:
        cfg.num_generations = args.num_generations
    if args.concurrency:
        cfg.concurrency = args.concurrency

    if args.plugins:
        entries = [e.strip() for e in args.plugins.split(",")]
        plugin_ids = resolve_plugin_ids(entries)
        cfg.plugins = [
            get_plugin(pid, cfg.generation, cfg.purpose,
                       num_tests=cfg.num_generations, concurrency=cfg.concurrency)
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
    elif cfg.target is not None:
        target = cfg.target
    else:
        parser.error(
            "no target configured — use --target-type rest|openai|function "
            "or add a 'target: type:' block to config.yaml"
        )

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
    print(f"Target          : {target.name}")
    print(f"Target purpose  : {cfg.purpose}")
    print(f"Generation model: {cfg.generation.name}")
    print(f"Grading model   : {cfg.grading.name}")
    print(f"Generations/plugin: {cfg.num_generations}")
    print(f"Concurrency     : {cfg.concurrency}")
    if cfg.strategies:
        print(f"Strategies      : {', '.join(s.id for s in cfg.strategies)}")
    print()

    # --- generate attacks -----------------------------------------------------
    all_plugin_results: list[tuple] = []
    if cfg.concurrency <= 1:
        for plugin in cfg.plugins:
            all_plugin_results.append(_run_plugin(plugin))
    else:
        with ThreadPoolExecutor(max_workers=cfg.concurrency) as pool:
            futures = {pool.submit(_run_plugin, pl): pl for pl in cfg.plugins}
            for future in as_completed(futures):
                all_plugin_results.append(future.result())

    # --- attack + grade -------------------------------------------------------
    all_records: list[dict] = []
    total = 0
    vulnerable = 0
    by_plugin: dict[str, dict] = {}

    for plugin, test_cases in all_plugin_results:
        augmented = (
            apply_strategies(test_cases, cfg.strategies, cfg.generation)
            if cfg.strategies else test_cases
        )
        strategy_note = (
            f", {len(augmented) - len(test_cases)} strategy-augmented"
            if cfg.strategies else ""
        )
        print(f"=== {plugin.id} ===")
        print(f"{len(test_cases)} base attack(s){strategy_note} → {len(augmented)} total\n")

        by_plugin[plugin.id] = {"total": 0, "vulnerable": 0}

        for i, case in enumerate(augmented, 1):
            strategy = case.metadata.get("strategy")
            tag = f"[{strategy}] " if strategy else ""
            print(f"  [{i}] {tag}{case.prompt}")

            response = target.generate(case.prompt)
            detector = get_detector(case.detector_id, cfg.grading)
            result = detector.grade(
                attack=case.prompt, response=response, purpose=cfg.purpose
            )

            verdict = "RESISTED " if result.passed else "VULNERABLE"
            print(f"       {verdict}  {result.reason}\n")

            all_records.append({
                "run_id":           run_id,
                "timestamp":        _now(),
                "plugin_id":        case.plugin_id,
                "detector_id":      case.detector_id,
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
            if not result.passed:
                vulnerable += 1
                by_plugin[plugin.id]["vulnerable"] += 1

        print()

    # --- summary --------------------------------------------------------------
    for counts in by_plugin.values():
        t = counts["total"]
        counts["pass_rate"] = round((t - counts["vulnerable"]) / t, 3) if t else 0.0

    summary = {
        "run_id":     run_id,
        "timestamp":  _now(),
        "total":      total,
        "vulnerable": vulnerable,
        "resisted":   total - vulnerable,
        "pass_rate":  round((total - vulnerable) / total, 3) if total else 0.0,
        "by_plugin":  by_plugin,
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
        bar = "█" * counts["vulnerable"] + "░" * (counts["total"] - counts["vulnerable"])
        print(f"  {pid:<30} {bar}  {counts['vulnerable']}/{counts['total']} vulnerable")
    print(f"\nResults → {out_file}")


if __name__ == "__main__":
    main()
