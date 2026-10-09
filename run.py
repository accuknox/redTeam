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
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from config import load_config
from detectors import all_detector_ids, get_detector
from findings import FindingsReport
from plugins import objective_for
from strategies import apply_strategies, plan_composition
from strategies.conversational import turn_instructions
from strategies.encoding import encoded_original

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
        amp, _ = plan_composition(cfg.strategies, compose=cfg.compose_strategies)
        if amp is not None:
            print(f"Composition     : '{amp.id}' wraps every other strategy "
                  f"(set compose_strategies: false for the flat expansion)")

    # An interactive strategy reads the target's reply to decide its next move,
    # so it cannot run in the strategy phase like a prompt-to-prompt transform:
    # its apply() is a pass-through by design. Split here and drive it at
    # evaluation time (as cli.py does) — otherwise the case runs single-shot on
    # the seed prompt and the run reports a multi-turn attack that never happened.
    # `apply_strategies` still builds their cases: apply() passing the prompt
    # through is what makes a correctly-tagged *seed* for the conversation.
    interactive_strategies = {s.id: s for s in cfg.strategies if s.interactive}
    for sid, s in interactive_strategies.items():
        print(f"Adaptive        : {sid} (up to {getattr(s, 'max_turns', '?')} turns per case)")
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
    by_strategy: dict[str, dict] = {}

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
                apply_strategies(test_cases, cfg.strategies, cfg.generation,
                                 compose=cfg.compose_strategies)
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

                detector = _detector_for(case, cfg.grading)
                # The attack's goal, given to the judge on every grading call so a
                # drifting turn is judged against what the attack is for rather
                # than against its literal final message.
                objective = objective_for(
                    case.plugin_id, case.detector_id, case.metadata
                )
                interactive = interactive_strategies.get(strategy or "")

                if interactive is not None:
                    # Multi-turn: the strategy owns the loop, grading each turn to
                    # decide whether to escalate, refine, or back off.
                    convo = interactive.run_conversation(
                        seed_prompt=case.prompt,
                        target=target,
                        grade=lambda a, r: detector.grade(
                            attack=a, response=r, purpose=cfg.purpose,
                            objective=objective),
                        generator=cfg.generation,
                        purpose=cfg.purpose,
                        objective=objective,
                        # Already resolved (per-plugin over global) when the plugin
                        # built the case, so refined turns inherit the same
                        # contract the seed prompt was generated under.
                        language=case.metadata.get("language") or "",
                        max_chars=case.metadata.get("max_chars") or 0,
                        instructions=turn_instructions(
                            case.detector_id,
                            case.metadata.get("generation_instructions") or ""),
                        examples=case.metadata.get("examples") or "",
                    )
                    attack_prompt = convo["attack"]
                    response = convo["response"]
                    result = convo["result"]
                    turns = convo["turns"]
                    transcript = convo["transcript"]
                    backtracks = convo.get("backtracks")
                    reconfirmed = convo.get("reconfirmed")
                else:
                    attack_prompt = case.prompt
                    turns, transcript, backtracks, reconfirmed = 1, None, None, None
                    response = target.generate(case.prompt)
                    result = detector.grade(
                        attack=case.prompt, response=response, purpose=cfg.purpose,
                        objective=objective, original=encoded_original(case),
                    )

                # passed is None when the judge gave no readable verdict: neither
                # a break nor a resist, so it is reported and then left out of the
                # counts rather than published as a finding.
                verdict = (
                    "ERROR" if result.passed is None
                    else "RESISTED" if result.passed
                    else "VULNERABLE"
                )
                turn_note = f"  ({turns} turns)" if turns > 1 else ""
                print(f"     {verdict}{turn_note}  {result.reason}\n")

                # --- map into the category/sub-category findings report --------
                # A multi-turn case is reported under the attack that actually
                # landed, with the seed kept as `original_prompt` — reporting the
                # benign opener as the attack would make the finding unreadable.
                report.add(
                    case=(case if interactive is None else replace(
                        case,
                        prompt=attack_prompt,
                        metadata={**case.metadata, "original_prompt": case.prompt},
                    )),
                    response=response,
                    result=result,
                )

                # --- write JSONL record ----------------------------------------
                record = {
                    "run_id":           run_id,
                    "timestamp":        _now(),
                    "plugin_id":        case.plugin_id,
                    "detector_id":      case.detector_id,
                    "strategy":         strategy,
                    # For a multi-turn case this is the attack that landed, which
                    # may be several refinements past the seed prompt.
                    "attack":           attack_prompt,
                    "original_prompt":  case.metadata.get("original_prompt") or (
                        case.prompt if interactive is not None else None),
                    "turns":            turns,
                    "transcript":       transcript,
                    "backtracks":       backtracks,
                    "reconfirmed":      reconfirmed,
                    "response":         response,
                    "passed":           result.passed,
                    "score":            result.score,
                    "reason":           result.reason,
                    "axes":             getattr(result, "axes", None),
                    "purpose":          cfg.purpose,
                    "generation_model": cfg.generation.name if cfg.generation else None,
                    "grading_model":    cfg.grading.name,
                }
                f.write(json.dumps(record) + "\n")

                # Baseline cases carry no strategy and bucket under "none", so the
                # lift a strategy buys over the raw prompt is readable off one table.
                strat_counts = by_strategy.setdefault(
                    strategy or "none", {"total": 0, "vulnerable": 0, "errored": 0}
                )

                if result.passed is None:
                    errored += 1
                    strat_counts["errored"] += 1
                    continue
                total += 1
                strat_counts["total"] += 1
                by_plugin[plugin.id]["total"] += 1
                if not result.passed:
                    vulnerable += 1
                    strat_counts["vulnerable"] += 1
                    by_plugin[plugin.id]["vulnerable"] += 1

            print()

        # --- write summary record -----------------------------------------------
        for pid, counts in by_plugin.items():
            t = counts["total"]
            counts["pass_rate"] = round((t - counts["vulnerable"]) / t, 3) if t else 0.0

        for counts in by_strategy.values():
            # `total` here is already decided-only (errored cases `continue`
            # before it is incremented), so this is a rate over graded cases.
            t = counts["total"]
            counts["attack_success_rate"] = (
                round(counts["vulnerable"] / t, 3) if t else 0.0
            )

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
            "by_strategy":  by_strategy or None,
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

    # With no strategies configured the single "none" row just restates the
    # totals above, so it is only worth printing once something ran alongside it.
    if len(by_strategy) > 1:
        print()
        print("By strategy (attack success rate):")
        baseline = by_strategy.get("none")
        col = max(len(s) for s in by_strategy) + 2
        ordered = sorted(
            by_strategy.items(),
            key=lambda kv: (kv[0] != "none", -kv[1]["attack_success_rate"]),
        )
        for sid, counts in ordered:
            lift = ""
            if baseline is not None and sid != "none":
                delta = counts["attack_success_rate"] - baseline["attack_success_rate"]
                lift = f"   {delta:+.0%} vs baseline"
            err = f"  ({counts['errored']} errored)" if counts["errored"] else ""
            print(f"  {sid:<{col}} {counts['attack_success_rate']:>5.0%}  "
                  f"({counts['vulnerable']}/{counts['total']}){err}{lift}")
        if min(c["total"] for c in by_strategy.values()) < 20:
            print("  note: fewer than 20 decided cases in some buckets — these "
                  "rates carry wide error bars.")
    print()
    print(f"Results written to {out_file}")
    print(f"Findings written to {findings_file}")


if __name__ == "__main__":
    args = sys.argv[1:]
    main(
        config_path=args[0] if len(args) > 0 else None,
        output_path=args[1] if len(args) > 1 else None,
    )
