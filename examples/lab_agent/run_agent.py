"""Run the lab agent against PwnGraph from a single command.

    python examples/lab_agent/run_agent.py            # uses mock LLM
    python examples/lab_agent/run_agent.py --real     # uses OPENAI_API_KEY

This is the quickstart entry point referenced in README.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Make `pwngraph` importable when running from the repo without install.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from examples.lab_agent.agent import build_agent
from pwngraph import PwnGraph


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PwnGraph against the lab agent.")
    parser.add_argument("--real", action="store_true", help="Use a real LLM (requires OPENAI_API_KEY).")
    parser.add_argument("--budget", type=int, default=30, help="Max adaptive probes NEXUS may run.")
    parser.add_argument("--baseline", type=int, default=3, help="Baseline benign runs.")
    parser.add_argument(
        "--attacks",
        default="all",
        choices=["all", "indirect_injection", "tool_poisoning"],
    )
    parser.add_argument("--out", default="examples/demo_outputs", help="Output directory.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    agent = build_agent(use_real_llm=args.real)

    pg = PwnGraph(agent=agent, seed=args.seed)
    pg.scan(
        attacks=args.attacks,
        budget=args.budget,
        baseline_runs=args.baseline,
        authorized=True,
    )

    out = pg.report(args.out)

    metrics = pg.metrics()
    print()
    print("=" * 60)
    print(f"Scan complete: {len(pg.dangerous_paths)} dangerous paths")
    for k, v in metrics.items():
        print(f"  {k:.<32} {v}")
    print(f"\n→ Report:        {out}")
    print(f"→ Graph JSON:    {Path(args.out) / 'graph.json'}")
    print("→ Interactive:   pwngraph serve  (http://127.0.0.1:8000)")
    print(f"→ Trace JSON:    {Path(args.out) / 'trace.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
