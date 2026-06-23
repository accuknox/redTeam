"""Config-driven red-team run.

Reads `config.yaml`, builds the configured plugins (each wired with the
generation model + target purpose + generation count), generates the adversarial
test cases, and grades them with the configured grading model.

    python run.py [path/to/config.yaml]

A target system under test plugs in where noted below — any `inference.Provider`
subclass. Until one is configured, this prints the generated attacks and the
grader wiring it would use.
"""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import load_config
from detectors import get_detector
from plugins import apply_strategies


def _generate_for_plugin(plugin):
    """Run a single plugin's generation (used as a thread-pool task)."""
    cases = plugin.generate_tests()
    return plugin, cases


def main(config_path: str | None = None) -> None:
    cfg = load_config(config_path) if config_path else load_config()

    print(f"Target purpose : {cfg.purpose}")
    print(f"Generation model: {cfg.generation.name}")
    print(f"Grading model   : {cfg.grading.name}")
    print(f"Generations/plugin: {cfg.num_generations}")
    print(f"Concurrency     : {cfg.concurrency}")
    if cfg.strategies:
        print(f"Strategies      : {', '.join(s.id for s in cfg.strategies)}")
    print()

    # --- Generate attacks (plugins run in parallel) ----------------------------
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

    for plugin, test_cases in all_results:
        augmented = (
            apply_strategies(test_cases, cfg.strategies, cfg.generation)
            if cfg.strategies
            else test_cases
        )

        strategy_note = (
            f", {len(augmented) - len(test_cases)} strategy-augmented"
            if cfg.strategies
            else ""
        )
        print(f"=== plugin: {plugin.id} ===")
        print(f"generated {len(test_cases)} base attack(s){strategy_note}, {len(augmented)} total\n")

        for i, case in enumerate(augmented, 1):
            strategy_tag = f"[{case.metadata['strategy']}] " if "strategy" in case.metadata else ""
            print(f"[{i}] {strategy_tag}{case.prompt}")

            from test_func import check_api_key
            response = check_api_key(case.prompt)
            detector = get_detector(case.detector_id, cfg.grading)
            result = detector.grade(attack=case.prompt, response=response,
                                    purpose=cfg.purpose)
            print(" final verdict  ", "RESISTED" if result.passed else "VULNERABLE", result.reason)

            # --- Attack the target -------------------------------------------------
            # Plug an inference.Provider in here, e.g.:
            #     response = target.generate(case.prompt, system=cfg.purpose)
            # then grade it with the configured grading model:
            #     detector = get_detector(case.detector_id, cfg.grading)
            #     result = detector.grade(attack=case.prompt, response=response,
            #                             purpose=cfg.purpose)
            #     print("   ", "RESISTED" if result.passed else "VULNERABLE", result.reason)

        print()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
