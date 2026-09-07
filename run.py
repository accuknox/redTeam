"""Config-driven red-team run.

Reads `config.yaml`, generates adversarial test cases, attacks the target, and
grades each response. Results are written to a JSONL file (one JSON object per
case) and a summary is appended at the end.

    python run.py [config.yaml] [output.jsonl]

Defaults: config.yaml in the same directory, results_<timestamp>.jsonl as output.
"""

from __future__ import annotations

import json
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from config import load_config
from detectors import all_detector_ids, get_detector
from findings import FindingsReport
from strategies import apply_strategies

#: Detector ids with a dedicated grader, resolved once at import.
_DETECTOR_IDS = frozenset(all_detector_ids())


def _detector_for(case, judge):
    """Resolve the grader for one case — dedicated first, CustomDetector second.

    Mirrors the dispatch in `cli.py`. Built-in plugins carry their own id as
    `detector_id` and grade against a response-voice rubric; user-defined plugins
    carry "custom" and grade against their configured objective.
    """
    if case.detector_id in _DETECTOR_IDS and case.detector_id != "custom":
        return get_detector(case.detector_id, judge)
    objective = case.metadata.get("objective")
    if objective:
        from detectors.custom import CustomDetector
        return CustomDetector(judge, objective=objective)
    return get_detector(case.detector_id, judge)


def _generate_for_plugin(plugin):
    cases = plugin.generate_tests()
    return plugin, cases


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(config_path: str | None = None, output_path: str | None = None) -> None:
    cfg = load_config(config_path) if config_path else load_config()

    run_id = str(uuid.uuid4())
    out_file = Path(output_path) if output_path else Path(
        f"results_{datetime.now().strftime('%Y%m%dT%H%M%S')}.jsonl"
    )
    # Category-mapped findings report, written alongside the flat JSONL log.
    findings_file = out_file.with_suffix(".findings.json")

    if cfg.target is not None:
        target = cfg.target
    else:
        raise RuntimeError(
            "no target configured — add a 'target: backend:' block to config.yaml"
        )

    print(f"Run ID          : {run_id}")
    print(f"Output          : {out_file}")
    print(f"Target          : {target.name}")
    print(f"Target purpose  : {cfg.purpose}")
    print(f"Generation model: {cfg.generation.name}")
    print(f"Grading model   : {cfg.grading.name}")
    print(f"Tests/plugin      : {cfg.num_tests}")
    print(f"Concurrency     : {cfg.concurrency}")
    if cfg.strategies:
        print(f"Strategies      : {', '.join(s.id for s in cfg.strategies)}")
    print()

    # --- Generate attacks -------------------------------------------------------
    all_results: list[tuple] = []

    if cfg.concurrency <= 1:
        for plugin in cfg.plugins:
            all_results.append(_generate_for_plugin(plugin))
    else:
        with ThreadPoolExecutor(max_workers=cfg.concurrency) as pool:
            futures = {
                pool.submit(_generate_for_plugin, p): p for p in cfg.plugins
            }
            for future in as_completed(futures):
                all_results.append(future.result())

    # --- Attack, grade, and write results ---------------------------------------
    total = 0
    vulnerable = 0
    errored = 0
    by_plugin: dict[str, dict] = {}

    report = FindingsReport(
        run_id=run_id,
        purpose=cfg.purpose,
        target_name=target.name,
        generation_model=cfg.generation.name,
        grading_model=cfg.grading.name,
    )

    with out_file.open("w", encoding="utf-8") as f:

        for plugin, test_cases in all_results:
            augmented = (
                apply_strategies(test_cases, cfg.strategies, cfg.generation)
                if cfg.strategies
                else test_cases
            )

            strategy_note = (
                f", {len(augmented) - len(test_cases)} strategy-augmented"
                if cfg.strategies else ""
            )
            print(f"=== plugin: {plugin.id} ===")
            print(f"generated {len(test_cases)} base attack(s){strategy_note}, {len(augmented)} total\n")

            by_plugin[plugin.id] = {"total": 0, "vulnerable": 0}

            for i, case in enumerate(augmented, 1):
                strategy = case.metadata.get("strategy")
                strategy_tag = f"[{strategy}] " if strategy else ""
                print(f"[{i}] {strategy_tag}{case.prompt}")

                response = target.generate(case.prompt)
                detector = _detector_for(case, cfg.grading)
                result = detector.grade(
                    attack=case.prompt, response=response, purpose=cfg.purpose
                )

                # passed is None when the judge gave no readable verdict: neither
                # a break nor a resist, so it is reported and then left out of the
                # counts rather than published as a finding.
                verdict = (
                    "ERROR" if result.passed is None
                    else "RESISTED" if result.passed
                    else "VULNERABLE"
                )
                print(f"     {verdict}  {result.reason}\n")

                # --- map into the category/sub-category findings report --------
                report.add(case=case, response=response, result=result)

                # --- write JSONL record ----------------------------------------
                record = {
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
                }
                f.write(json.dumps(record) + "\n")

                if result.passed is None:
                    errored += 1
                    continue
                total += 1
                by_plugin[plugin.id]["total"] += 1
                if not result.passed:
                    vulnerable += 1
                    by_plugin[plugin.id]["vulnerable"] += 1

            print()

        # --- write summary record -----------------------------------------------
        for pid, counts in by_plugin.items():
            t = counts["total"]
            counts["pass_rate"] = round((t - counts["vulnerable"]) / t, 3) if t else 0.0

        summary = {
            "run_id":       run_id,
            "type":         "summary",
            "timestamp":    _now(),
            "total":        total,
            "vulnerable":   vulnerable,
            "resisted":     total - vulnerable,
            # Cases the judge could not grade. Excluded from total and pass_rate:
            # a grading failure is not evidence about the target either way.
            "errored":     errored,
            "pass_rate":    round((total - vulnerable) / total, 3) if total else 0.0,
            "by_plugin":    by_plugin,
        }
        f.write(json.dumps(summary) + "\n")

    # --- write the category-mapped findings file --------------------------------
    report.write(findings_file)

    # --- print summary ----------------------------------------------------------
    print("=" * 50)
    print(f"Total cases  : {total}")
    print(f"Vulnerable   : {vulnerable}")
    print(f"Resisted     : {total - vulnerable}")
    if errored:
        print(f"Errored      : {errored}  (judge gave no readable verdict — "
              f"not counted; check the grading model)")
    print(f"Pass rate    : {summary['pass_rate']:.0%}")
    print()
    print("By plugin:")
    for pid, counts in by_plugin.items():
        print(f"  {pid}: {counts['vulnerable']}/{counts['total']} vulnerable "
              f"({1 - counts['pass_rate']:.0%})")
    print()
    print(f"Results written to {out_file}")
    print(f"Findings written to {findings_file}")


if __name__ == "__main__":
    args = sys.argv[1:]
    main(
        config_path=args[0] if len(args) > 0 else None,
        output_path=args[1] if len(args) > 1 else None,
    )
