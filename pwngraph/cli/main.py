"""``pwngraph`` CLI.

Usage:
    pwngraph scan --target path/to/agent_module.py:build_agent \
                  --attacks all --budget 25 --authorized --out ./out
    pwngraph version
    pwngraph list-attacks
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import re
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from pwngraph import __version__
from pwngraph.core import PwnGraph

console = Console()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )
    # The neo4j driver logs every server-side "notification" (GqlStatusObject
    # dumps — schema/performance hints like "this constraint already exists"
    # or "dynamic properties can't use an index") at INFO, which floods the
    # scan output with driver internals no user asked for. --verbose means
    # "more detail about the scan," not "dump raw protocol notifications" —
    # keep this quiet even then.
    logging.getLogger("neo4j").setLevel(logging.WARNING)


def _load_profile(name_or_path: str) -> dict:
    """Resolve a scan profile by built-in name or file path.

    Built-in profiles ship in ``pwngraph/profiles/*.yaml`` (quick, full,
    owasp-llm, paranoid). A path to any YAML file works too.
    """
    import yaml

    path = Path(name_or_path)
    if not path.exists():
        builtin = Path(__file__).parent.parent / "profiles" / f"{name_or_path}.yaml"
        if builtin.exists():
            path = builtin
        else:
            available = sorted(
                p.stem for p in (Path(__file__).parent.parent / "profiles").glob("*.yaml")
            )
            raise click.BadParameter(
                f"unknown profile '{name_or_path}'. "
                f"Built-in profiles: {', '.join(available)}. "
                f"Or pass a path to a profile YAML file."
            )
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise click.BadParameter(f"profile {path} is not a valid YAML mapping")
    return data


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="pwngraph")
def cli() -> None:
    """PwnGraph — the runtime attack graph engine for AI agents."""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--target",
    required=True,
    help=(
        "Path to a Python file and a factory function that returns a LangChain "
        "agent, in the form 'path/to/file.py:build_agent'. The factory must "
        "take no required arguments."
    ),
)
@click.option(
    "--attacks",
    default="all",
    type=click.Choice(
        [
            "all",
            "indirect_injection",
            "tool_poisoning",
            "prompt_exfiltration",
            "shell_injection",
            "file_read_injection",
            "memory_poisoning",
        ]
    ),
    help="Which attack class(es) to run. 'all' runs all 6.",
)
@click.option(
    "--authorized",
    is_flag=True,
    default=False,
    help=(
        "Required: an explicit acknowledgment that the target is one you own or have "
        "written permission to test. NEXUS probes autonomously, deciding its own next "
        "move with no human reviewing each step — this is the boundary that keeps that "
        "autonomy scoped. See README.md's 'Responsible Use'."
    ),
)
@click.option(
    "--budget",
    default=25,
    show_default=True,
    type=int,
    help="Interaction budget: the max number of adaptive probes NEXUS may run.",
)
@click.option(
    "--nexus-level",
    default=1,
    show_default=True,
    type=click.IntRange(1, 5),
    help=(
        "Adaptive autonomy/depth, 1 (basic probe/observe) to 5 (deep multi-step chain "
        "pursuit with reasoner-backed hypotheses). Higher levels reason harder per probe — "
        "they don't run more probes; --budget alone controls that."
    ),
)
@click.option(
    "--exhaustive",
    is_flag=True,
    default=False,
    help=(
        "Disable the confidence-based early stop: by default NEXUS stops once every "
        "class/tool has at least one attempt and confidence is high, which can leave a "
        "class that failed its one probe never retried. With this on, NEXUS only stops "
        "on budget exhaustion or a genuine dead end — every class gets a real, "
        "multi-attempt shot."
    ),
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Enumerate the agent's tool surface and exit without running any attacks.",
)
@click.option(
    "--out",
    default="./pwngraph_out",
    show_default=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Output directory for graph.json, trace.json, findings.sarif, poc/.",
)
@click.option(
    "--profile",
    default=None,
    help=(
        "Named preset (quick, full, owasp-llm, paranoid) or path to a profile "
        "YAML. Sets attacks/budget/baseline-runs. Any flag you pass "
        "explicitly overrides the profile."
    ),
)
@click.option("--seed", default=None, type=int, help="Seed for reproducible runs.")
@click.option(
    "--payload",
    default=None,
    type=click.Path(exists=True, path_type=Path),
    help=(
        "Path to a custom payload YAML file (or directory of YAML files). "
        "Skips built-in fuzzer templates and delivers your payload(s) instead. "
        "Built-in attack classes still run unless --attacks is omitted."
    ),
)
@click.option(
    "--payload-only",
    is_flag=True,
    default=False,
    help="When --payload is given, skip all built-in attack classes and run only custom payloads.",
)
@click.option(
    "--payload-trials",
    default=1,
    show_default=True,
    type=int,
    help=(
        "With --payload: re-deliver each custom payload this many times. >1 turns "
        "single observations into an Attack Success Rate (successes/trials) with a "
        "95% CI. Has no effect on NEXUS's own probes — it decides for itself "
        "whether a hit is worth re-probing."
    ),
)
@click.option(
    "--baseline-runs",
    default=3,
    show_default=True,
    type=int,
    help="Number of benign baseline runs before fuzzing.",
)
@click.option(
    "--recon-budget",
    default=6,
    show_default=True,
    type=int,
    help=(
        "Max new agent calls spent on pre-attack recon (elicit the agent's stated "
        "purpose, confirm tool-to-tool chains) before any adversarial payload — see "
        "pwngraph.recon. Set to 0 to skip recon's own calls (tool profiling from the "
        "baseline still runs for free)."
    ),
)
@click.option(
    "--input-key",
    default=None,
    help=(
        "Override the input key passed to the agent's .invoke() (e.g. 'question', "
        "'query'). Auto-detected from the agent's input_keys when omitted."
    ),
)
@click.option(
    "--max-calls",
    default=None,
    type=int,
    help="Hard cap on total agent invocations. Stops early when reached (cost guard).",
)
@click.option(
    "--save-baseline",
    default=None,
    type=click.Path(dir_okay=False, path_type=Path),
    help=(
        "Save this scan's dangerous paths to a JSON baseline file. "
        "Compare a later scan against it with `pwngraph diff`."
    ),
)
@click.option(
    "--llm-model",
    default="gpt-4o-mini",
    show_default=True,
    help="Advanced: model used to generate attack payloads (reads OPENAI_API_KEY).",
)
@click.option(
    "--llm-temperature",
    default=0.8,
    show_default=True,
    type=float,
    help="Advanced: sampling temperature for payload generation.",
)
@click.option(
    "--payload-cache",
    default=None,
    type=click.Path(dir_okay=False, path_type=Path),
    help=(
        "Advanced: replay generated payloads from (and record into) this JSON "
        "file when --seed is also set, for reproducible re-runs (e.g. `pwngraph "
        "diff`). Off by default — a scan is genuinely dynamic every run unless "
        "you opt in."
    ),
)
@click.option("--no-progress", is_flag=True, default=False, help="Disable the progress bar.")
@click.option(
    "--open/--no-open",
    "open_report",
    default=True,
    show_default=True,
    help="Open this scan in the running `pwngraph serve` viewer when the scan finishes.",
)
@click.option(
    "--neo4j-uri",
    default=None,
    envvar="PWNGRAPH_NEO4J_URI",
    help="Neo4j connection URI. Default: bolt://localhost:7687 (env: PWNGRAPH_NEO4J_URI).",
)
@click.option(
    "--neo4j-user",
    default=None,
    envvar="PWNGRAPH_NEO4J_USER",
    help="Neo4j username. Default: neo4j (env: PWNGRAPH_NEO4J_USER).",
)
@click.option(
    "--neo4j-password",
    default=None,
    envvar="PWNGRAPH_NEO4J_PASSWORD",
    help="Neo4j password. Default: pwngraph-dev, matching docker-compose.yml (env: PWNGRAPH_NEO4J_PASSWORD).",
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging.")
def scan(
    target: str,
    profile: str | None,
    attacks: str,
    baseline_runs: int,
    payload_trials: int,
    out: Path,
    seed: int | None,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
    save_baseline: Path | None,
    payload: Path | None,
    payload_only: bool,
    input_key: str | None,
    max_calls: int | None,
    recon_budget: int,
    llm_model: str,
    llm_temperature: float,
    payload_cache: Path | None,
    dry_run: bool,
    no_progress: bool,
    open_report: bool,
    nexus_level: int,
    budget: int,
    exhaustive: bool,
    authorized: bool,
    verbose: bool,
) -> None:
    """Run a PwnGraph scan against a target agent.

    Requires a reachable Neo4j — run `pwngraph doctor` first if unsure, or
    `docker compose up -d` to start the bundled dev instance.
    """
    _setup_logging(verbose)

    # --dry-run only enumerates the tool surface (no LLM calls, no adversarial
    # probing, nothing autonomous) — the authorization acknowledgment exists
    # for NEXUS's autonomous decision-making, which dry-run never reaches.
    if not authorized and not dry_run:
        raise click.UsageError(
            "scan requires --authorized: an explicit acknowledgment that the target is "
            "one you own or have written permission to test (NEXUS probes autonomously, "
            "with no human reviewing each step). Re-run with --authorized once that's true."
        )

    # Apply a profile preset. Values only fill in flags the user left at their
    # default — anything passed explicitly on the command line wins.
    if profile is not None:
        prof = _load_profile(profile)
        ctx = click.get_current_context()

        def _from_default(name: str) -> bool:
            return ctx.get_parameter_source(name) == click.core.ParameterSource.DEFAULT

        if "attacks" in prof and _from_default("attacks"):
            attacks = prof["attacks"]
        if "budget" in prof and _from_default("budget"):
            budget = int(prof["budget"])
        if "baseline_runs" in prof and _from_default("baseline_runs"):
            baseline_runs = int(prof["baseline_runs"])
        if "nexus_level" in prof and _from_default("nexus_level"):
            nexus_level = int(prof["nexus_level"])
        if "exhaustive" in prof and _from_default("exhaustive"):
            exhaustive = bool(prof["exhaustive"])
        console.print(f"Profile : [green]{prof.get('name', profile)}[/green]")

    console.rule("[bold blue]PwnGraph scan[/bold blue]")
    console.print(f"Target  : [cyan]{target}[/cyan]")
    console.print(f"Attacks : [cyan]{attacks}[/cyan]")
    console.print(f"Baseline: [cyan]{baseline_runs}[/cyan] benign runs")
    if max_calls:
        console.print(f"Budget  : [yellow]max {max_calls} calls[/yellow]")
    console.print(f"Output  : [cyan]{out}[/cyan]")
    console.print(
        f"NEXUS   : [magenta]level={nexus_level}[/magenta]  budget={budget} adaptive probes"
        + ("  [yellow]exhaustive[/yellow]" if exhaustive else "")
    )

    agent = _load_agent(target)

    # Dry-run enumerates the tool surface only — no Neo4j connection needed,
    # so it stays a genuinely zero-cost, zero-infra check.
    if dry_run:
        from pwngraph.connector import make_connector
        from pwngraph.preflight import dry_run as do_dry_run

        connector = make_connector(agent, input_key=input_key)
        result = do_dry_run(connector)
        console.print(f"\nTarget : [bold]{result.target_name}[/bold]")
        console.print(f"Tools  : {len(result.tools)}")
        for t in result.tools:
            console.print(
                f"  [blue]{t.name}[/blue]  "
                f"data_sink={t.is_data_sink}  action_sink={t.is_action_sink}  "
                f"tags={t.tags}"
            )
        for w in result.warnings:
            console.print(f"[yellow]⚠  {w}[/yellow]")
        if not result.testable:
            console.print("\n[red]No tools found — scan would test almost nothing.[/red]")
        else:
            console.print("\n[green]Ready to scan.[/green]")
        return

    graph_backend = _make_graph_backend(neo4j_uri, neo4j_user, neo4j_password)
    from pwngraph.fuzzer.llm_generator import make_default_client

    try:
        llm_client = make_default_client(model=llm_model, temperature=llm_temperature)
    except RuntimeError as exc:
        raise click.UsageError(str(exc)) from exc
    pg = PwnGraph(
        agent=agent,
        seed=seed,
        input_key=input_key,
        graph_backend=graph_backend,
        llm_client=llm_client,
        payload_cache_path=str(payload_cache) if payload_cache else None,
    )

    # Load custom payloads if supplied. Pass the agent's tool names so templates
    # declaring `requires_tool` are skipped when the agent lacks that tool.
    custom_payloads = None
    if payload is not None:
        from pwngraph.fuzzer.custom_payload import load_payloads

        agent_tools = {t.name for t in pg.connector.list_tools()}
        all_loaded = load_payloads(payload)
        custom_payloads = [
            p for p in all_loaded if not (p.requires_tool and p.requires_tool not in agent_tools)
        ]
        skipped = len(all_loaded) - len(custom_payloads)
        msg = f"Custom  : [magenta]{len(custom_payloads)} payload(s) from {payload}[/magenta]"
        if skipped:
            msg += f" [dim]({skipped} skipped — required tool absent)[/dim]"
        console.print(msg)

    effective_attacks = "none" if (payload_only and custom_payloads) else attacks
    paths = pg.scan(
        attacks=effective_attacks,
        budget=budget,
        baseline_runs=baseline_runs,
        payload_trials=payload_trials,
        max_calls=max_calls,
        progress=not no_progress,
        custom_payloads=custom_payloads,
        recon_budget=recon_budget,
        nexus_level=nexus_level,
        nexus_exhaustive=exhaustive,
        authorized=authorized,
    )

    pg.run_static_analysis(target)

    _print_recon(pg.target_profile)

    pg.report(out)
    metrics = pg.metrics()

    if save_baseline is not None:
        from pwngraph.baseline import save_baseline as _save_baseline
        from pwngraph.baseline import save_baseline_grade as _save_baseline_grade

        _save_baseline(paths, save_baseline)
        _save_baseline_grade(pg.risk_grade(), save_baseline)
        console.print(f"Baseline: [cyan]{save_baseline}[/cyan] ({len(paths)} path(s))")

    table = Table(title="Scan metrics", show_header=False)
    for k, v in metrics.items():
        table.add_row(k, str(v))
    console.print(table)

    if pg.nexus_state is not None:
        ns = pg.nexus_state
        nexus_table = Table(title="NEXUS", show_header=False)
        nexus_table.add_row("status", ns.status.value)
        nexus_table.add_row("iterations", f"{ns.iteration}/{ns.budget}")
        nexus_table.add_row("successful_techniques", ", ".join(ns.successful_techniques) or "none")
        nexus_table.add_row("failed_techniques", ", ".join(ns.failed_techniques) or "none")
        nexus_table.add_row("discovered_tools", str(len(ns.discovered_capabilities)))
        nexus_table.add_row("confidence", f"{ns.confidence:.2f}")
        console.print(nexus_table)

    _print_asr(pg.asr)
    _print_owasp(pg.owasp_coverage())
    _print_evidence_ladder(pg.structural_graph)

    # #13 — single-line risk verdict
    grade = pg.risk_grade()
    grade_color = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
    console.print(
        Panel(
            f"[{grade_color.get(grade['grade'], 'white')}]"
            f"RISK GRADE: {grade['grade']}  (score {grade['score']}/100)[/]\n"
            f"{grade['interpretation']}\n"
            f"[dim]findings={len(pg.findings)}  "
            f"ASR={metrics.get('attack_success_rate', 0)*100:.0f}%  "
            f"OWASP detected={sum(1 for r in pg.owasp_coverage() if r['status']=='detected')}[/dim]",
            title="Verdict",
            border_style="blue",
        )
    )

    if paths:
        console.print(f"\n[bold red]Found {len(paths)} dangerous attack paths[/bold red]")
    else:
        console.print(
            "\n[bold green]No dangerous paths found.[/bold green] "
            "Consider raising --budget or expanding attack classes."
        )
    scan_url = f"http://127.0.0.1:8000/scans/{pg.graph_builder.scan_id}"
    console.print(f"\n→ Report : [bold cyan]{scan_url}[/bold cyan]  [dim](pwngraph serve)[/dim]")
    console.print(f"→ Graph  : [bold]{pg.graph_path}[/bold]  [dim](offline JSON snapshot)[/dim]")
    console.print(f"→ Trace  : [bold]{out / 'trace.json'}[/bold]")
    console.print(f"→ SARIF  : [bold]{out / 'findings.sarif'}[/bold]")
    if pg.structural_graph is not None:
        console.print(f"→ Surface: [bold]{out / 'evidence_ladder.json'}[/bold]")
    console.print(
        f"[dim]Findings, CVSS, remediation and the risk grade are stored in Neo4j "
        f"(scan_id={pg.graph_builder.scan_id}) — run `pwngraph serve` and open the URL "
        f"above, query it with `pwngraph query --scan-id {pg.graph_builder.scan_id}`, "
        f"or read it directly via Cypher (e.g. Neo4j Browser).[/dim]"
    )

    if open_report:
        # Only open if a viewer is actually listening — launching a browser at
        # a dead port would show "connection refused", which is worse than
        # printing the two commands that get there.
        if _port_is_open("127.0.0.1", 8000) and _open_url(scan_url):
            console.print("[dim]Opened this scan in the running viewer.[/dim]")
        else:
            console.print(
                f"[dim]No viewer running — start one with "
                f"[bold]pwngraph serve[/bold], then open {scan_url}[/dim]"
            )


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("baseline", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--target", required=True, help="Same --target locator as `pwngraph scan`.")
@click.option(
    "--attacks",
    default="all",
    type=click.Choice(
        [
            "all",
            "indirect_injection",
            "tool_poisoning",
            "prompt_exfiltration",
            "shell_injection",
            "file_read_injection",
            "memory_poisoning",
        ]
    ),
    help="Which attack class(es) to run for the comparison scan.",
)
@click.option("--budget", default=25, show_default=True, type=int)
@click.option("--baseline-runs", default=3, show_default=True, type=int)
@click.option("--nexus-level", default=1, show_default=True, type=click.IntRange(1, 5))
@click.option("--exhaustive", is_flag=True, default=False)
@click.option(
    "--authorized",
    is_flag=True,
    default=False,
    help=(
        "Required: an explicit acknowledgment that the target is one you own or have "
        "written permission to test. See `pwngraph scan --help`."
    ),
)
@click.option("--seed", default=None, type=int, help="Seed for reproducible runs.")
@click.option("--neo4j-uri", default=None, envvar="PWNGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default=None, envvar="PWNGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default=None, envvar="PWNGRAPH_NEO4J_PASSWORD")
@click.option("--max-calls", default=None, type=int)
@click.option("--no-progress", is_flag=True, default=False)
@click.option(
    "--fail-on-severity",
    default="high",
    show_default=True,
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Fail on a new dangerous path at or above this severity, regardless of "
    "whether other paths closed in the same scan.",
)
@click.option(
    "--fail-on-regression/--no-fail-on-regression",
    default=True,
    show_default=True,
    help="CI gate: exit 1 on a new path at/above --fail-on-severity, or a risk-grade "
    "regression versus the baseline (when the baseline recorded one — see "
    "`scan --save-baseline`).",
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging.")
def diff(
    baseline: Path,
    target: str,
    attacks: str,
    budget: int,
    baseline_runs: int,
    nexus_level: int,
    exhaustive: bool,
    authorized: bool,
    seed: int | None,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
    max_calls: int | None,
    no_progress: bool,
    fail_on_severity: str,
    fail_on_regression: bool,
    verbose: bool,
) -> None:
    """Scan TARGET and diff the result against a saved BASELINE.

    The regression story: scan today with `pwngraph scan --save-baseline
    before.json`, apply a guardrail, then re-scan and compare —

        pwngraph diff before.json --target adapter.py:build_agent --authorized

    Exits 1 on a new dangerous path at or above --fail-on-severity (default
    high), or a risk-grade regression versus the baseline, so this drops
    straight into a CI gate. A new LOW-severity path alone does not fail the
    build by default — raise or lower the bar with --fail-on-severity.
    """
    _setup_logging(verbose)
    from pwngraph.attackpath import diff_paths, newly_reachable_severities
    from pwngraph.baseline import load_baseline, load_baseline_grade
    from pwngraph.types import Severity

    if not authorized:
        raise click.UsageError(
            "diff requires --authorized: an explicit acknowledgment that the target is "
            "one you own or have written permission to test (NEXUS probes autonomously, "
            "with no human reviewing each step). Re-run with --authorized once that's true."
        )

    console.rule("[bold blue]PwnGraph diff[/bold blue]")
    console.print(f"Baseline: [cyan]{baseline}[/cyan]")
    console.print(f"Target  : [cyan]{target}[/cyan]")

    before = load_baseline(baseline)
    before_grade = load_baseline_grade(baseline)
    console.print(f"[dim]{len(before)} path(s) in baseline[/dim]")

    agent = _load_agent(target)
    graph_backend = _make_graph_backend(neo4j_uri, neo4j_user, neo4j_password)
    pg = PwnGraph(agent=agent, seed=seed, graph_backend=graph_backend)
    after = pg.scan(
        attacks=attacks,
        budget=budget,
        baseline_runs=baseline_runs,
        nexus_level=nexus_level,
        nexus_exhaustive=exhaustive,
        max_calls=max_calls,
        progress=not no_progress,
        authorized=authorized,
    )
    after_grade = pg.risk_grade()

    result = diff_paths(before, after)
    summary = result.summary()

    table = Table(title="Path diff")
    table.add_column("Category")
    table.add_column("Count", justify="right")
    table.add_row("[red]new[/red]", str(summary["new"]))
    table.add_row("[green]removed[/green]", str(summary["removed"]))
    table.add_row("persisting", str(summary["persisting"]))
    console.print(table)

    if result.new:
        console.print("\n[bold red]New dangerous paths:[/bold red]")
        for p in result.new:
            console.print(f"  [{p.severity.value}] {p.description}")

    if result.removed:
        console.print("\n[bold green]Closed dangerous paths:[/bold green]")
        for p in result.removed:
            console.print(f"  [{p.severity.value}] {p.description}")

    if result.improved:
        console.print(
            "\n[bold green]Defense effective — dangerous paths closed, none new.[/bold green]"
        )
    elif result.regressed:
        console.print("\n[bold red]Regression — new dangerous path(s), none closed.[/bold red]")
    elif not result.new and not result.removed:
        console.print("\n[dim]No change in dangerous paths.[/dim]")
    else:
        console.print("\n[yellow]Mixed change — some paths closed, some new.[/yellow]")

    # Risk grade — always shown; only gates the build when a baseline grade
    # exists to compare against (older baselines simply skip this check).
    console.print(
        f"\nRisk grade: [bold]{after_grade['grade']}[/bold] (score {after_grade['score']}/100)"
        + (
            f"  [dim](baseline was {before_grade['grade']}, score {before_grade['score']})[/dim]"
            if before_grade
            else "  [dim](no grade recorded in this baseline — nothing to compare)[/dim]"
        )
    )

    threshold = Severity(fail_on_severity)
    new_at_or_above = [s for s in newly_reachable_severities(result) if s.score >= threshold.score]
    grade_regressed = before_grade is not None and after_grade["score"] > before_grade["score"]

    if new_at_or_above:
        console.print(
            f"[red]{len(new_at_or_above)} new path(s) at or above "
            f"--fail-on-severity={fail_on_severity}[/red]"
        )
    if grade_regressed:
        console.print(
            f"[red]Risk grade regressed: {before_grade['grade']} "
            f"(score {before_grade['score']}) -> {after_grade['grade']} "
            f"(score {after_grade['score']})[/red]"
        )

    if fail_on_regression and (new_at_or_above or grade_regressed):
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("name", required=False)
@click.option(
    "--scan-id",
    default=None,
    help="Scope the query to one scan (the scan_id printed at the end of `pwngraph scan`). "
    "Omit to read across every scan the database currently holds.",
)
@click.option(
    "--tool",
    default=None,
    help="Tool name argument for queries that need one (currently only blast-radius).",
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Print raw JSON rows.")
@click.option("--neo4j-uri", default=None, envvar="PWNGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default=None, envvar="PWNGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default=None, envvar="PWNGRAPH_NEO4J_PASSWORD")
def query(
    name: str | None,
    scan_id: str | None,
    tool: str | None,
    as_json: bool,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
) -> None:
    """Run a named query against a persisted scan's graph.

    Run with no NAME to list every available query:

        pwngraph query

    Don't have a scan_id handy? `scans` lists every scan currently in the
    database, most recent first:

        pwngraph query scans

    Then run one, optionally scoped to a single scan:

        pwngraph query dangerous-outcomes --scan-id 1f1081d6
        pwngraph query exfil-findings --json
        pwngraph query blast-radius --tool web_search --scan-id 1f1081d6
    """
    from pwngraph.queries import QUERY_REGISTRY
    from pwngraph.queries import run as run_query

    if name is None:
        table = Table(title="Available queries")
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("OWASP", no_wrap=True)
        table.add_column("Description")
        for q in QUERY_REGISTRY.values():
            table.add_row(q.name, ", ".join(q.owasp) or "-", q.description)
        console.print(table)
        console.print(
            "\n[dim]Run `pwngraph query <name>` [--scan-id ID] [--tool NAME] [--json][/dim]"
        )
        return

    if name not in QUERY_REGISTRY:
        available = ", ".join(sorted(QUERY_REGISTRY))
        raise click.BadParameter(f"unknown query {name!r}. Available: {available}")

    if QUERY_REGISTRY[name].requires_tool and not tool:
        raise click.BadParameter(f"query {name!r} requires --tool <name>")

    graph_backend = _make_graph_backend(neo4j_uri, neo4j_user, neo4j_password)
    rows = run_query(name, graph_backend, scan_id=scan_id, tool=tool)

    if as_json:
        import json

        console.print(json.dumps(rows, indent=2, default=str))
        return

    if not rows:
        console.print("[dim]No rows.[/dim]")
        return

    table = Table(title=name)
    for col in rows[0]:
        table.add_column(col)
    for row in rows:
        table.add_row(*(str(v) for v in row.values()))
    console.print(table)


# ---------------------------------------------------------------------------
# graph
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--scan-id",
    required=True,
    help="scan_id to export — don't have one handy? `pwngraph query scans` lists every "
    "scan in the database.",
)
@click.option(
    "--out",
    default="graph.json",
    show_default=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Where to write the exported graph.",
)
@click.option("--target", default="", help="Label shown in the graph payload (optional).")
@click.option("--neo4j-uri", default=None, envvar="PWNGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default=None, envvar="PWNGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default=None, envvar="PWNGRAPH_NEO4J_PASSWORD")
def graph(
    scan_id: str,
    out: Path,
    target: str,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
) -> None:
    """Re-export a graph.json snapshot for a previously-run scan.

    `pwngraph scan` already writes graph.json automatically — this is for
    revisiting a scan from an earlier session, without re-running it, since
    Neo4j keeps every scan's graph around until you clear it yourself. This
    is an offline JSON artifact for CI/archival; to actually browse a graph,
    run `pwngraph serve` instead — it reads Neo4j live, no export needed.

        pwngraph query scans                    # find a scan_id
        pwngraph graph --scan-id 1f1081d6
    """
    from pwngraph.reporter.graph_export import export_graph_json

    graph_backend = _make_graph_backend(neo4j_uri, neo4j_user, neo4j_password)
    path = export_graph_json(graph_backend, scan_id, out, target_name=target)
    console.print(f"[green]Wrote {path}[/green]")


# ---------------------------------------------------------------------------
# delete-scan
# ---------------------------------------------------------------------------


@cli.command("delete-scan")
@click.argument("scan_id")
@click.option("--yes", is_flag=True, default=False, help="Skip the confirmation prompt.")
@click.option("--neo4j-uri", default=None, envvar="PWNGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default=None, envvar="PWNGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default=None, envvar="PWNGRAPH_NEO4J_PASSWORD")
def delete_scan_cmd(
    scan_id: str,
    yes: bool,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
) -> None:
    """Permanently delete one scan's data from Neo4j — graph, report, and
    static surface. There is no undo.

    Nothing else in PwnGraph ever removes a scan once written — this is the
    only retention lever the database has. Don't have a scan_id handy?
    `pwngraph query scans` lists every scan currently in the database.

        pwngraph delete-scan 1f1081d6
    """
    from pwngraph.queries import delete_scan, list_scans

    graph_backend = _make_graph_backend(neo4j_uri, neo4j_user, neo4j_password)
    rows = [r for r in list_scans(graph_backend) if r["scan_id"] == scan_id]
    if not rows:
        raise click.ClickException(
            f"No scan_id={scan_id!r} found. Run `pwngraph query scans` to list what's there."
        )
    row = rows[0]

    console.rule("[bold red]Delete scan[/bold red]")
    console.print(f"scan_id : [cyan]{scan_id}[/cyan]")
    console.print(f"target  : {row.get('target_name') or row.get('target_id') or 'unknown'}")
    console.print(f"nodes   : {row['nodes']}")

    if not yes and not click.confirm("\nPermanently delete this scan? This cannot be undone."):
        console.print("[dim]Aborted — nothing deleted.[/dim]")
        return

    deleted = delete_scan(graph_backend, scan_id)
    console.print(f"[green]Deleted {deleted} node(s) for scan_id={scan_id}.[/green]")


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to.")
@click.option("--port", default=8000, show_default=True, type=int, help="Port to bind to.")
@click.option(
    "--reload",
    is_flag=True,
    default=False,
    help="Enable uvicorn autoreload (development only, restarts on code changes).",
)
@click.option("--neo4j-uri", default=None, envvar="PWNGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default=None, envvar="PWNGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default=None, envvar="PWNGRAPH_NEO4J_PASSWORD")
@click.option(
    "--token",
    default=None,
    envvar="PWNGRAPH_API_TOKEN",
    help=(
        "Require this bearer token on every /api/* request (env: PWNGRAPH_API_TOKEN). "
        "The API is read-only but reads back everything a scan captured — set this "
        "whenever --host isn't 127.0.0.1/localhost."
    ),
)
def serve(
    host: str,
    port: int,
    reload: bool,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
    token: str | None,
) -> None:
    """Serve the live graph/findings viewer — FastAPI, reading straight from Neo4j.

    Reads the same database every `pwngraph scan` writes to — no export
    step, no file to go stale, no pyvis/NetworkX involved. Requires the
    `serve` extra:

        pip install 'pwngraph[serve]'
        pwngraph serve
        # -> http://127.0.0.1:8000

    Serves the built React frontend too, when present
    (`pwngraph/api/static/` — see `frontend/README.md`); otherwise this runs
    API-only, for developing the frontend against its own dev server
    (`npm run dev`, proxied to this port).

    No auth is required by default — reasonable for a loopback-only server,
    but this API reads back everything a scan captured. Pass --token (or set
    PWNGRAPH_API_TOKEN) whenever --host makes this reachable from anywhere
    else; the browser can use it as either an Authorization header or a
    ?token= query parameter.
    """
    try:
        import uvicorn
    except ImportError as exc:
        raise click.ClickException(
            "The 'serve' extra is required: pip install 'pwngraph[serve]'"
        ) from exc

    import os

    from pwngraph.api.app import create_app

    uri = neo4j_uri or os.environ.get("PWNGRAPH_NEO4J_URI", "bolt://localhost:7687")
    user = neo4j_user or os.environ.get("PWNGRAPH_NEO4J_USER", "neo4j")
    password = neo4j_password or os.environ.get("PWNGRAPH_NEO4J_PASSWORD", "pwngraph-dev")
    static_dir = Path(__file__).resolve().parent.parent / "api" / "static"

    console.rule("[bold blue]PwnGraph serve[/bold blue]")
    console.print(f"→ http://{host}:{port}")
    if not (static_dir.is_dir() and any(static_dir.iterdir())):
        console.print(
            f"[yellow]No built frontend at {static_dir} — serving the API only. "
            "Run the frontend's own dev server (npm run dev) alongside this "
            "during development.[/yellow]"
        )

    is_loopback = host in ("127.0.0.1", "localhost", "::1")
    if token:
        console.print("[dim]API token required on every /api/* request.[/dim]")
    elif not is_loopback:
        console.print(
            f"[bold red]⚠  Binding to {host} with no --token set.[/bold red] "
            "[red]Every scan this reads back — findings, tool output, anything "
            "an agent leaked — is served to anyone who can reach this host with "
            "no authentication. Stop and pass --token, or set "
            "PWNGRAPH_API_TOKEN.[/red]"
        )

    if reload:
        # uvicorn's autoreloader re-imports the app in a subprocess, so it
        # needs an import-string factory (create_app_from_env), not an
        # already-built app object — propagate the resolved connection
        # details via env vars so that subprocess targets the same server.
        os.environ["PWNGRAPH_NEO4J_URI"] = uri
        os.environ["PWNGRAPH_NEO4J_USER"] = user
        os.environ["PWNGRAPH_NEO4J_PASSWORD"] = password
        if token:
            os.environ["PWNGRAPH_API_TOKEN"] = token
        uvicorn.run(
            "pwngraph.api.app:create_app_from_env",
            factory=True,
            host=host,
            port=port,
            reload=True,
        )
        return

    graph_backend = _make_graph_backend(neo4j_uri, neo4j_user, neo4j_password)
    app = create_app(
        graph_backend, static_dir=static_dir if static_dir.is_dir() else None, api_token=token
    )
    uvicorn.run(app, host=host, port=port)


# ---------------------------------------------------------------------------
# docker-compose
# ---------------------------------------------------------------------------


@cli.command("docker-compose")
@click.option(
    "--out",
    default="docker-compose.yml",
    show_default=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Where to write the compose file.",
)
@click.option("--force", is_flag=True, default=False, help="Overwrite an existing file.")
def docker_compose_cmd(out: Path, force: bool) -> None:
    """Write the bundled Neo4j docker-compose.yml to the current directory.

    Every scan needs a reachable Neo4j — `pip install pwngraph` alone doesn't
    get you one, because pip installs a package's Python code, not
    project-root scaffolding files. Run this once, then:

        docker compose up -d
        pwngraph doctor

    If you cloned the repo instead of installing from PyPI, you already have
    docker-compose.yml at the repo root — this command is for everyone else.
    """
    if out.exists() and not force:
        raise click.ClickException(f"{out} already exists. Pass --force to overwrite.")

    src = Path(__file__).resolve().parent.parent / "resources" / "docker-compose.yml"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    console.print(f"[green]Wrote {out}[/green]")
    console.print(
        "Next: [bold cyan]docker compose up -d[/bold cyan] "
        "then [bold cyan]pwngraph doctor[/bold cyan]"
    )


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


@cli.command()
def doctor() -> None:
    """Check that the environment is ready to run a scan."""
    from pwngraph.preflight import doctor as run_checks
    from pwngraph.preflight import summarize

    checks = run_checks()
    table = Table(title="Environment checks")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")

    for c in checks:
        if c.ok:
            status = "[green]OK[/green]"
        elif c.level == "required":
            status = "[bold red]FAIL[/bold red]"
        elif c.level == "optional":
            status = "[yellow]WARN[/yellow]"
        else:
            status = "[dim]INFO[/dim]"
        table.add_row(c.name, status, c.detail)

    console.print(table)
    ready, summary = summarize(checks)
    color = "green" if ready else "red"
    console.print(f"\n[{color}]{summary}[/{color}]")


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


@cli.command("init")
@click.argument(
    "path",
    required=False,
    default=".",
    type=click.Path(exists=True, path_type=Path),
)
@click.option(
    "--out",
    default="adapter.py",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Where to write the adapter file (default: adapter.py).",
)
@click.option(
    "--target",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Agent file to scan directly, bypassing search. Overrides PATH.",
)
def init_cmd(path: Path, out: Path, target: Path | None) -> None:
    """Generate adapter.py for your agent — just run `pwngraph init`.

    PATH is where to look (default: current directory) — a directory is
    searched recursively for the most likely agent file, a file is used
    directly. When OPENAI_API_KEY is set and static analysis can't confidently
    read the agent's tools/entry point off the source itself, PwnGraph falls
    back to asking GPT-4o-mini.

    No flags required:

        export OPENAI_API_KEY=sk-...
        pwngraph init

    Search a different directory, or point at one file directly:

        pwngraph init path/to/project
        pwngraph init --target path/to/my_agent.py
    """
    import os

    console.rule("[bold blue]PwnGraph Init[/bold blue]")

    api_key = os.getenv("OPENAI_API_KEY")

    # ── Resolve the agent file ────────────────────────────────────────────────
    # --target always wins (an explicit file). Otherwise PATH: a file is used
    # directly, a directory is searched recursively (so `pwngraph init` from a
    # repo root finds an agent sitting in a subfolder, not just the cwd).
    agent_file = target
    search_root = path if path.is_dir() else path.parent
    if agent_file is None and path.is_file():
        agent_file = path
        console.print(f"[green]Using    :[/green] [cyan]{agent_file}[/cyan]")
    if agent_file is None:
        agent_file = _find_agent_file(search_root)
        if agent_file is not None:
            console.print(f"[green]Detected :[/green] [cyan]{agent_file}[/cyan]")
        else:
            console.print(f"[yellow]No agent file found under {search_root}.[/yellow]")

    # ── Structural analysis — always run, always shown ─────────────────────────
    # Independent of LLM vs. template generation below: this is a local, free,
    # deterministic AST read of the file so you can see exactly what PwnGraph
    # thinks your agent's callable surface looks like before anything is
    # generated. Framework-based agents (LangChain/LangGraph) mostly show up
    # here as "no plain-Python entry point" since their tools/entry point are
    # framework objects, not bare functions — that's expected and fine.
    plain_analysis = None
    if agent_file is not None:
        from pwngraph.scaffold import analyze_plain_agent

        plain_analysis = analyze_plain_agent(agent_file)
        if plain_analysis.all_functions:
            console.print(
                f"[dim]Functions found in {agent_file.name}: "
                f"{', '.join(plain_analysis.all_functions)}[/dim]"
            )
        if plain_analysis.tools:
            tool_names = ", ".join(n for n, _ in plain_analysis.tools)
            console.print(f"[green]Tools    :[/green] {tool_names}")
        if plain_analysis.entry_function:
            console.print(
                f"[green]Entry pt :[/green] {plain_analysis.entry_function}() "
                f"[dim](confidence: {plain_analysis.entry_confidence})[/dim]"
            )
        console.print()

    # ── LLM-powered mode — the primary path whenever a key is available ─────────
    # Always tried first when OPENAI_API_KEY is set, regardless of how confident
    # the static analysis above was. The analysis result is handed in as
    # grounding facts (real module name, discovered entry point / tools) so the
    # model has ground truth instead of having to infer everything from source,
    # and its output is validated (syntax, build_agent() present, no leftover
    # placeholders — see _llm_generate_adapter) before being trusted.
    if agent_file is not None and api_key:
        console.print("[green]Mode     :[/green] LLM-powered")
        console.print()
        ok = _llm_generate_adapter(agent_file, out, analysis=plain_analysis)
        if ok:
            budget = _suggested_budget(plain_analysis)
            console.print(f"\n[bold green]Generated:[/bold green] {out}")
            console.print()
            console.print("Next steps:")
            console.print(
                f"  1. [bold cyan]pwngraph scan --target {out}:build_agent --dry-run[/bold cyan]"
                "    ← verify tool count"
            )
            console.print(
                f"  2. [bold cyan]pwngraph scan --target {out}:build_agent --attacks all "
                f"--budget {budget} --authorized --out ./out[/bold cyan]"
            )
            console.print()
            console.print(
                "[dim]If --dry-run shows 0 tools, run `pwngraph init --target <file>` and point at the correct agent file.[/dim]"
            )
            return
        console.print("[yellow]LLM generation failed validation — falling back.[/yellow]")
        console.print()

    # ── Deterministic plain-Python adapter — fallback only ──────────────────────
    # Reached only when there's no API key, or the LLM call above failed
    # validation. Static analysis being confident here still means it's exact
    # (read straight off the real parsed source) — a safety net, not the
    # primary path.
    if agent_file is not None and plain_analysis is not None and plain_analysis.is_usable:
        from pwngraph.scaffold import generate_plain_adapter

        console.print("[green]Mode     :[/green] Static analysis (deterministic fallback, no LLM)")
        generate_plain_adapter(
            module=agent_file.stem,
            entry_function=plain_analysis.entry_function,
            tools=plain_analysis.tools,
            tools_dict_name=plain_analysis.tools_dict_name,
            output_path=out,
        )
        budget = _suggested_budget(plain_analysis)
        console.print(f"[bold green]Generated:[/bold green] {out}")
        console.print()
        console.print(
            "[dim]Verify _ENTRY_FUNCTION and _TOOL_DESCRIPTIONS at the top of the "
            f"file match your agent, then:[/dim]"
        )
        console.print(f"  [bold cyan]pwngraph scan --target {out}:build_agent --dry-run[/bold cyan]")
        console.print(
            f"  [bold cyan]pwngraph scan --target {out}:build_agent --attacks all "
            f"--budget {budget} --authorized --out ./out[/bold cyan]"
        )
        return

    if agent_file is not None and not api_key:
        console.print(
            "[yellow]OPENAI_API_KEY not set — falling back to interactive template.[/yellow]\n"
            "[dim]Tip: export OPENAI_API_KEY=<key> and re-run `pwngraph init` for zero-config generation.[/dim]"
        )
        console.print()

    # ── Interactive template fallback ─────────────────────────────────────────
    from pwngraph.scaffold import detect_project, generate_adapter

    with console.status("[dim]Scanning project...[/dim]"):
        result = detect_project(Path("."))

    if result.framework != "unknown":
        console.print(f"[green]Framework:[/green] {result.framework.replace('_', ' ').title()}")
    else:
        console.print(
            "[yellow]Framework not recognised — generic adapter will be generated.[/yellow]"
        )

    if result.factory_hint:
        console.print(f"[dim]Factory  : {result.factory_hint} (in {result.module_hint})[/dim]")
    console.print()

    _FW_CHOICES = click.Choice(
        [
            "langgraph_react",
            "langgraph_stategraph",
            "langchain_executor",
            "langchain_react",
            "unknown",
        ]
    )
    framework = click.prompt("Framework ", default=result.framework, type=_FW_CHOICES)
    module = click.prompt("Module    ", default=result.module_hint or "your_module")
    cls = click.prompt("Factory   ", default=result.factory_hint or "build_agent")
    input_key = click.prompt("Input key ", default=result.input_key_hint)

    console.print()
    generate_adapter(
        framework=framework, module=module, cls=cls, input_key=input_key, output_path=out
    )

    console.print(f"[bold green]Generated:[/bold green] {out}")
    console.print()
    console.print("[dim]Edit the EDIT 1 and EDIT 2 sections in the file, then:[/dim]")
    console.print(f"  [bold cyan]pwngraph scan --target {out}:build_agent --dry-run[/bold cyan]")
    console.print(
        f"  [bold cyan]pwngraph scan --target {out}:build_agent --attacks all "
        "--budget 25 --authorized --out ./out[/bold cyan]"
    )


# ---------------------------------------------------------------------------
# list-attacks
# ---------------------------------------------------------------------------


@cli.command("list-attacks")
def list_attacks() -> None:
    """List the attack classes supported in this release."""
    table = Table(title="PwnGraph attack classes")
    table.add_column("ID", no_wrap=True)
    table.add_column("Class", no_wrap=True)
    table.add_column("OWASP LLM 2025", no_wrap=True)
    table.add_column("Description")
    table.add_row(
        "indirect_injection",
        "Indirect Prompt Injection",
        "LLM01, LLM08",
        "Poisoned documents the agent reads through file/web tools.",
    )
    table.add_row(
        "tool_poisoning",
        "Tool Output Poisoning",
        "LLM01, LLM05",
        "Malicious responses injected into tools the agent calls.",
    )
    table.add_row(
        "prompt_exfiltration",
        "System Prompt Exfiltration",
        "LLM07, LLM02",
        "Trick the agent into leaking its system prompt or internal instructions.",
    )
    table.add_row(
        "shell_injection",
        "Shell / Code Injection",
        "LLM06, LLM05",
        "Drive an agent with ShellTool/PythonREPL to execute attacker-chosen commands.",
    )
    table.add_row(
        "file_read_injection",
        "Sensitive File Read",
        "LLM02, LLM06",
        "Path traversal attacks to read /etc/passwd, .env, SSH keys, config files.",
    )
    table.add_row(
        "memory_poisoning",
        "Memory / History Poisoning",
        "LLM01, LLM08",
        "Inject false facts or policies into the agent's conversation memory / KB.",
    )
    console.print(table)
    console.print(
        "\n[dim]Findings escalate to LLM06 (Excessive Agency) whenever the chain "
        "drives a tool action or exfiltration. Out of scope by design: "
        "LLM03 (supply chain), LLM04 (model poisoning), LLM09 (misinformation).[/dim]"
    )


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@cli.command()
def version() -> None:
    """Print PwnGraph version."""
    console.print(f"pwngraph {__version__}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _print_recon(target_profile: Any) -> None:
    """Render recon's pre-attack profile — stated purpose, confirmed chains,
    and the top of the derived attack plan. ``None`` when the scan never ran
    recon (should not happen for a scan through this CLI, but this stays
    honest for callers of the Python API that skip it)."""
    if target_profile is None:
        return

    console.rule("[bold blue]Recon[/bold blue]")
    if target_profile.purpose_probes:
        first = target_profile.purpose_probes[0]
        console.print(f"[dim]Q: {first.question}\nA: {first.answer[:200]}[/dim]")
    console.print(f"Objective : [cyan]{target_profile.objective}[/cyan]")

    confirmed = [c for c in target_profile.chains if c.kind == "confirmed_chain"]
    if confirmed:
        chains_str = ", ".join(f"{c.source_tool}→{c.target_tool}" for c in confirmed)
        console.print(f"Chains    : [red]{chains_str}[/red] (confirmed)")

    table = Table(title="Attack plan (top targets)", show_header=True)
    table.add_column("Rank", justify="right")
    table.add_column("Attack class")
    table.add_column("Target tool")
    table.add_column("Rationale")
    for item in target_profile.attack_plan[:3]:
        table.add_row(
            str(item.rank), item.attack_class, item.target_tool or "—", item.rationale
        )
    console.print(table)


def _print_asr(asr: dict) -> None:
    """Render the Attack Success Rate rollup (overall + per attack class)."""
    if not asr:
        return
    overall = asr.get("overall", {})
    by_class = asr.get("by_class", {})

    table = Table(title="Attack Success Rate (ASR)")
    table.add_column("Scope")
    table.add_column("ASR", justify="right")
    table.add_column("95% CI", justify="right")
    table.add_column("succ/trials", justify="right")
    table.add_column("max sev")

    def _row(label: str, b: dict) -> None:
        asr_pct = f"{b.get('asr', 0.0) * 100:.0f}%"
        ci = f"{b.get('wilson_low', 0.0) * 100:.0f}–{b.get('wilson_high', 0.0) * 100:.0f}%"
        st = f"{b.get('successes', 0)}/{b.get('trials', 0)}"
        table.add_row(label, asr_pct, ci, st, b.get("max_severity", "info"))

    for cls, bucket in sorted(by_class.items()):
        _row(cls, bucket)
    if overall:
        _row("[bold]overall[/bold]", overall)
    console.print(table)

    succ = overall.get("payloads_successful", 0)
    tot = overall.get("payloads_total", 0)
    if tot:
        console.print(f"[dim]{succ}/{tot} distinct payloads succeeded at least once.[/dim]")


def _print_owasp(coverage: list[dict]) -> None:
    """Render the OWASP LLM Top-10 (2025) coverage matrix."""
    if not coverage:
        return
    style = {
        "detected": "bold red",
        "tested": "green",
        "partial": "yellow",
        "out-of-scope": "dim",
    }
    table = Table(title="OWASP LLM Top 10 (2025) coverage")
    table.add_column("ID")
    table.add_column("Category")
    table.add_column("Status")
    for r in coverage:
        st = r["status"]
        label = st if st != "detected" else f"detected ({r['count']})"
        table.add_row(r["id"], r["name"], f"[{style.get(st, 'white')}]{label}[/]")
    console.print(table)


def _print_evidence_ladder(structural_graph: Any) -> None:
    """Render the possible/observed/validated/exploited surface, when static
    analysis ran (module-style targets skip it — see run_static_analysis)."""
    if structural_graph is None:
        return

    style = {
        "possible": "dim",
        "observed": "cyan",
        "validated": "yellow",
        "exploited": "bold red",
    }
    coverage = structural_graph.coverage()
    if not coverage:
        return

    table = Table(title="Evidence ladder (static + runtime)")
    table.add_column("State")
    table.add_column("Tools", justify="right")
    for state in ("possible", "observed", "validated", "exploited"):
        count = coverage.get(state, 0)
        if count:
            table.add_row(f"[{style[state]}]{state}[/]", str(count))
    console.print(table)

    untested = [n.name for n in structural_graph.possible_only]
    if untested:
        console.print(
            f"[dim]Never touched by this scan: {', '.join(sorted(untested))} — "
            f"the part of the attack surface more iterations or a different "
            f"attack class might still reach.[/dim]"
        )


_ADAPTER_SYSTEM_PROMPT = """\
You are a PwnGraph adapter generator. PwnGraph is a security testing tool for AI agents.
It needs an adapter.py containing ONE function — build_agent() — that returns a live,
callable agent instance. PwnGraph calls this function to get an agent to attack.

You will receive Python source code for an AI agent you have never seen before.
Your job is to produce a working adapter.py no matter what the agent looks like.

Output ONLY valid Python code. No markdown. No code fences. No explanation.

STEP 0 — decide if this is a FRAMEWORK agent or a PLAIN-PYTHON agent:

    FRAMEWORK agent — the source imports langchain or langgraph.
    → Follow STEP 1 through STEP 6 below (the LangChain/LangGraph path).

    PLAIN-PYTHON agent — no langchain/langgraph import anywhere. This is
    very common: a hand-rolled loop around openai.OpenAI(...).chat.completions
    .create(...) or anthropic.Anthropic(...).messages.create(...), with tools
    dispatched from a name->function dict (e.g. TOOLS = {"foo": foo_fn}) or an
    if/elif chain. DO NOT invent LangChain/LangGraph objects for this case —
    there is nothing to import and the result will not run. Instead, generate
    a shim that drives the agent's OWN entry function directly and reports its
    OWN tool calls to PwnGraph's tracer, unmodified:

        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent))

        import <source_module> as _agent_module

        # The one function that takes one turn of user text and returns the
        # agent's reply — e.g. run_agent(text), chat(text), respond(text).
        _ENTRY_FUNCTION = "<entry_function_name>"
        # The dict variable name whose values are the tool functions, if the
        # source has one (e.g. "TOOLS"); otherwise None.
        _TOOLS_DICT_NAME = "<dict_name_or_None>"
        # Every tool function name paired with its docstring/description.
        _TOOL_DESCRIPTIONS = [("tool_name", "description"), ...]

        class _ShimTool:
            def __init__(self, name, description, fn):
                self.name = name
                self.description = description
                self._fn = fn

            def _run(self, *args, **kwargs):
                return self._fn(*args, **kwargs)

        class _ShimAgent:
            def __init__(self):
                self.tools = [
                    _ShimTool(name, desc, getattr(_agent_module, name))
                    for name, desc in _TOOL_DESCRIPTIONS
                    if hasattr(_agent_module, name)
                ]

            def invoke(self, inputs, config=None):
                import json as _json
                import uuid
                callbacks = (config or {}).get("callbacks") or []
                user_input = inputs.get("input", "")
                tools_dict = (
                    getattr(_agent_module, _TOOLS_DICT_NAME, None)
                    if _TOOLS_DICT_NAME else None
                )

                def _make_wrapper(tool):
                    def wrapper(*args, **kwargs):
                        rid = uuid.uuid4()
                        try:
                            arg_str = _json.dumps(kwargs if kwargs else list(args))
                        except TypeError:
                            arg_str = str(kwargs or args)
                        for cb in callbacks:
                            if hasattr(cb, "on_tool_start"):
                                cb.on_tool_start({"name": tool.name}, arg_str, run_id=rid)
                        try:
                            result = tool._run(*args, **kwargs)
                        except Exception as exc:
                            for cb in callbacks:
                                if hasattr(cb, "on_tool_error"):
                                    cb.on_tool_error(exc, run_id=rid)
                            raise
                        for cb in callbacks:
                            if hasattr(cb, "on_tool_end"):
                                cb.on_tool_end(output=str(result), run_id=rid)
                        return result
                    return wrapper

                originals = {}
                for tool in self.tools:
                    original = getattr(_agent_module, tool.name, None)
                    if original is None:
                        continue
                    originals[tool.name] = original
                    wrapped = _make_wrapper(tool)
                    setattr(_agent_module, tool.name, wrapped)
                    if isinstance(tools_dict, dict) and tool.name in tools_dict:
                        tools_dict[tool.name] = wrapped

                try:
                    entry = getattr(_agent_module, _ENTRY_FUNCTION)
                    output = entry(user_input)
                finally:
                    for name, original in originals.items():
                        setattr(_agent_module, name, original)
                        if isinstance(tools_dict, dict) and name in tools_dict:
                            tools_dict[name] = original

                for cb in callbacks:
                    if hasattr(cb, "on_agent_finish"):
                        cb.on_agent_finish(
                            type("Finish", (), {"return_values": {"output": output}})()
                        )
                return {"output": output}

        def build_agent():
            return _ShimAgent()

    Fill in _ENTRY_FUNCTION, _TOOLS_DICT_NAME, and _TOOL_DESCRIPTIONS from your
    own reading of the source (a user message may also hand you these facts
    already extracted by static analysis — trust those unless the source
    clearly contradicts them). NEVER reimplement a tool function's body —
    only reference it by name; the shim imports and instruments the real one.
    If this is a PLAIN-PYTHON agent, output the shim above (adjusted for the
    real module/entry/tools) and SKIP STEP 1 through STEP 6 entirely.

STEP 1 — sys.path (always add, safe even when not needed):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

STEP 2 — environment loading:
    If the source calls load_dotenv() or reads os.environ, preserve it:
    from dotenv import load_dotenv
    load_dotenv()

STEP 3 — detect and import the LLM provider (match what you see in the source):
    from langchain_openai import ChatOpenAI            # default: model="gpt-4o-mini"
    from langchain_anthropic import ChatAnthropic      # model="claude-3-haiku-20240307"
    from langchain_google_genai import ChatGoogleGenerativeAI  # model="gemini-2.0-flash"
    from langchain_groq import ChatGroq                # model="llama3-8b-8192"
    from langchain_ollama import ChatOllama            # model="llama3"
    If the LLM is unclear: default to ChatOpenAI(model="gpt-4o-mini")

STEP 4 — detect and IMPORT ALL tools. NEVER produce tools = [].

    CRITICAL: Do NOT copy, redefine, or reimplement any tool function.
    ALWAYS import tools from the source module by name. Example:

        from lab_agent import web_search, read_file, run_command, send_email

    This preserves docstrings (required by @tool) and avoids duplication.

    What to import:
    a) Every @tool-decorated function defined in the source file → import by name
    b) Tool objects assigned to variables → import those variables
    c) LangChain built-in tools already imported in source → import those same classes
    d) Tools from langchain_community.tools → import them directly
    When in doubt: include the tool rather than exclude it.

STEP 5 — detect the agent framework and build accordingly:

    LangGraph (create_react_agent) — most common:
        from langgraph.prebuilt import create_react_agent
        return create_react_agent(model=llm, tools=tools)

    LangGraph StateGraph — compile and return the graph.

    LangChain AgentExecutor:
        from langchain.agents import AgentExecutor, create_tool_calling_agent
        from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
        prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a helpful assistant."),
            MessagesPlaceholder("chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder("agent_scratchpad"),
        ])
        agent = create_tool_calling_agent(llm, tools, prompt)
        return AgentExecutor(agent=agent, tools=tools)

    If unclear: use LangGraph create_react_agent.

STEP 6 — handle the factory:
    CASE A: source has a zero-arg factory (def build_agent(), def get_agent(), etc.)
            → call it directly inside your build_agent()
    CASE B: factory requires args (session_id, user_id, config, etc.)
            → call with sensible defaults (None, "", 0) or build the agent yourself
    CASE C: no factory at all → assemble the agent from the parts you found

    The output function MUST be named build_agent() and take NO arguments.

OUTPUT FORMAT — raw Python only:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

    from dotenv import load_dotenv   # only if source uses it
    load_dotenv()

    from langchain_openai import ChatOpenAI
    from langgraph.prebuilt import create_react_agent

    # IMPORT tools from the source module — never redefine them
    from <source_module> import tool_a, tool_b, tool_c

    def build_agent():
        llm = ChatOpenAI(model="gpt-4o-mini")
        tools = [tool_a, tool_b, tool_c]
        return create_react_agent(model=llm, tools=tools)
"""


_AGENT_FILE_SKIP_DIRS = {
    "venv", ".venv", "__pycache__", ".git", "node_modules", "dist", "build",
    ".tox", ".pytest_cache", "site-packages",
}
_AGENT_FILE_SKIP_PREFIXES = ("test_", "conftest", "setup", "adapter", "_")

# Keyword shortlist — cheap and fast, but inherently incomplete (it can only
# name providers/frameworks we thought of). It's a first pass, not the source
# of truth: any file it misses still gets a real chance via the structural
# fallback below, which reads actual code shape instead of matching strings.
_AGENT_KEYWORD_SIGNALS = [
    "@tool", "build_agent", "create_react_agent", "AgentExecutor",
    "ChatOpenAI", "ChatGoogleGenerativeAI", "ChatGroq", "ChatAnthropic",
    "langgraph", "langchain", "tool_calling_agent",
    "chat.completions.create", "client.chat.completions",
    "openai.OpenAI", "anthropic.Anthropic", "tool_calls", "function_call",
    "TOOL_SCHEMAS", "SYSTEM_PROMPT", '"role": "system"', "'role': 'system'",
]


def _candidate_py_files(scan_dir: Path) -> list[Path]:
    return [
        f for f in sorted(scan_dir.rglob("*.py"))
        if not any(part in _AGENT_FILE_SKIP_DIRS for part in f.parts)
        and not f.name.startswith(_AGENT_FILE_SKIP_PREFIXES)
    ]


def _suggested_budget(analysis: Any) -> int:
    """A --budget suggestion sized to what was actually discovered.

    More tools means more surface for NEXUS to spread probes across before
    every class/tool combination has even one real attempt — the generic
    default (25) undersells a wide tool surface and oversells a narrow one.
    """
    tools = getattr(analysis, "tools", None) if analysis is not None else None
    if not tools:
        return 25
    return max(25, len(tools) * 3)


def _find_agent_file(scan_dir: Path) -> Path | None:
    """Return the most likely agent Python file under scan_dir (recursive).

    Two passes:
      1. Keyword shortlist — fast, but only as complete as the keyword list.
      2. Structural fallback — when no file matches a keyword, actually parse
         every candidate with the same AST analysis `pwngraph init` uses for
         adapter generation, and pick whichever one it reads most confidently
         as an agent (a real entry point + tool functions). This is what lets
         detection hold up for a codebase that doesn't mention any provider
         name literally, instead of only ever knowing the providers/frameworks
         this keyword list happens to name.
    """
    candidates: list[tuple[int, Path]] = []
    for py_file in _candidate_py_files(scan_dir):
        try:
            text = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        score = sum(text.count(sig) for sig in _AGENT_KEYWORD_SIGNALS)
        if score > 0:
            candidates.append((score, py_file))

    if candidates:
        candidates.sort(key=lambda x: -x[0])
        return candidates[0][1]

    # Structural fallback — no keyword hit anywhere; ask the AST analyzer.
    from pwngraph.scaffold import analyze_plain_agent

    _CONF_RANK = {"high": 2, "medium": 1, "none": 0}
    best: tuple[int, int, Path] | None = None  # (confidence_rank, n_tools, path)
    for py_file in _candidate_py_files(scan_dir):
        analysis = analyze_plain_agent(py_file)
        if not analysis.is_usable:
            continue
        key = (_CONF_RANK.get(analysis.entry_confidence, 0), len(analysis.tools), py_file)
        if best is None or key[:2] > best[:2]:
            best = key
    return best[2] if best else None


def _static_check_adapter_code(code: str) -> str | None:
    """Cheap checks that don't require running anything. Returns an error
    message on failure, or None if they all pass."""
    try:
        compile(code, "<adapter>", "exec")
    except SyntaxError as exc:
        return f"syntax error: {exc}"
    if "def build_agent" not in code:
        return "no build_agent() function"
    leaked = re.findall(r"<[A-Za-z_][A-Za-z0-9_ ]{0,40}>", code)
    if leaked:
        return f"unfilled placeholder(s) left in the output: {', '.join(sorted(set(leaked)))}"
    return None


def _validate_adapter_runs(out: Path) -> str | None:
    """Actually import the adapter, call build_agent(), and enumerate its
    tools — catches the class of bug static checks can't, like a name that's
    inconsistent with how it was imported (``from mod import x`` but the rest
    of the code does ``getattr(mod, ...)``, as gpt-4o-mini did once here).

    Returns an error message (the traceback) on failure, or None on success.
    This genuinely runs the target agent file's top-level code, same as a
    real scan moments later would — no new trust boundary crossed.
    """
    import importlib.util
    import sys
    import traceback as _tb
    import uuid

    mod_name = f"_pwngraph_adapter_validate_{uuid.uuid4().hex}"
    parent = str(out.parent.resolve())
    path_added = parent not in sys.path
    if path_added:
        sys.path.insert(0, parent)
    try:
        spec = importlib.util.spec_from_file_location(mod_name, str(out))
        if spec is None or spec.loader is None:
            return "could not load the generated adapter as a module"
        module = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = module
        spec.loader.exec_module(module)

        agent = module.build_agent()

        from pwngraph.connector import make_connector

        tools = make_connector(agent).list_tools()
        if not tools:
            return "build_agent() ran, but list_tools() found zero tools"
        return None
    except Exception:  # noqa: BLE001 — the traceback is the point
        return _tb.format_exc()
    finally:
        sys.modules.pop(mod_name, None)
        if path_added:
            try:
                sys.path.remove(parent)
            except ValueError:
                pass


def _llm_generate_adapter(source_path: Path, out: Path, analysis: Any = None) -> bool:
    """Use GPT-4o-mini to read source_path and write a pre-filled adapter to out.

    ``analysis`` is the optional ``PlainAgentAnalysis`` from the local AST pass
    (see ``pwngraph.scaffold.analyze_plain_agent``) — when it found a tool
    inventory / entry point, those facts are handed to the model as grounding
    so it doesn't have to (mis)infer them from source alone, and doesn't force
    a framework-less agent into a LangChain shape it doesn't have.

    The output is never trusted on the model's word: it's syntax-checked,
    then actually imported and run (``_validate_adapter_runs``). A failure at
    either stage is fed straight back to the model for one self-correction
    attempt before giving up — a static/AST read can prove code is *plausible*,
    only actually running it proves it *works*.

    Returns True on success, False if the API key is missing, openai is
    unavailable, or both generation attempts failed validation.
    """
    import os

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return False

    try:
        from openai import OpenAI
    except ImportError:
        console.print("[yellow]openai package not found — falling back to template.[/yellow]")
        return False

    source = source_path.read_text(encoding="utf-8")
    client = OpenAI(api_key=api_key)

    # The module name is never ambiguous — we know it from the filename. Hand
    # it over as a fact so there's no placeholder for the model to leave
    # unfilled (this is exactly what went wrong before: it echoed the prompt's
    # own "<source_module>" example literally instead of substituting it).
    hints = [f"The real Python module name to import is: {source_path.stem}"]
    if analysis is not None and (analysis.tools or analysis.entry_function):
        if analysis.entry_function:
            hints.append(
                f"Likely entry point: {analysis.entry_function}(user_text) "
                f"(confidence: {analysis.entry_confidence})"
            )
        if analysis.tools:
            names = ", ".join(n for n, _ in analysis.tools)
            hints.append(f"Tool functions: {names}")
        if analysis.tools_dict_name:
            hints.append(f"Dispatch dict: {analysis.tools_dict_name}")
    hints.append("Treat these as ground truth unless the source clearly contradicts them.")
    user_content = (
        f"Generate adapter.py for this agent:\n\n```python\n{source}\n```\n\n"
        + "\n".join(hints)
    )

    messages: list[dict[str, str]] = [
        {"role": "system", "content": _ADAPTER_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

    for attempt in range(2):
        status = "Asking GPT-4o-mini to analyse" if attempt == 0 else "Asking GPT-4o-mini to fix its own output for"
        with console.status(f"[dim]{status} {source_path.name}…[/dim]"):
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages,
                temperature=0,
            )

        code = resp.choices[0].message.content.strip()
        # Strip markdown fences if the model added them despite the instruction
        if code.startswith("```"):
            lines = code.splitlines()
            start = 1
            end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
            code = "\n".join(lines[start:end])

        static_error = _static_check_adapter_code(code)
        if static_error is not None:
            console.print(f"[yellow]⚠ LLM output failed a static check: {static_error}[/yellow]")
            error_for_retry = static_error
        else:
            # Write it where it will actually be scanned from (relative
            # imports inside it depend on this), then really run it.
            out.write_text(code, encoding="utf-8")
            error_for_retry = _validate_adapter_runs(out)
            if error_for_retry is None:
                return True
            console.print(
                "[yellow]⚠ Generated adapter raised an error when actually run "
                f"(see below) — {'retrying once' if attempt == 0 else 'giving up'}.[/yellow]"
            )
            console.print(f"[dim]{error_for_retry.strip().splitlines()[-1]}[/dim]")

        if attempt == 0:
            messages.append({"role": "assistant", "content": code})
            messages.append({
                "role": "user",
                "content": (
                    "That code failed when actually run. Fix it and output the "
                    "complete corrected adapter.py (raw Python only, same rules as "
                    f"before). The error was:\n\n{error_for_retry}"
                ),
            })

    return False


def _port_is_open(host: str, port: int, timeout: float = 0.35) -> bool:
    """Is something listening there? Used to avoid opening a browser at a
    viewer that isn't running — "connection refused" is a worse answer than
    printing the command that starts it."""
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _open_url(url: str) -> bool:
    """Open a URL in the user's default browser, returning whether it
    (probably) worked.

    Handles native Linux/macOS/Windows via the stdlib ``webbrowser`` module,
    with a WSL fallback that hands the URL to the Windows shell — inside WSL
    ``webbrowser`` is usually a no-op.
    """
    import os
    import subprocess
    import webbrowser

    is_wsl = "microsoft" in os.uname().release.lower() if hasattr(os, "uname") else False
    if is_wsl:
        try:
            subprocess.Popen(
                ["explorer.exe", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except Exception:  # noqa: BLE001 — fall through to webbrowser
            pass

    try:
        return bool(webbrowser.open(url))
    except Exception:  # noqa: BLE001
        return False


def _make_graph_backend(uri: str | None, user: str | None, password: str | None):
    """Construct the Neo4jBackend for this scan from CLI flags / env vars.

    Falls back to ``pwngraph.backend``'s own ``PWNGRAPH_NEO4J_*`` env-var
    defaults for any value left unset — see that module for the concrete
    default connection string.
    """
    from pwngraph.backend import make_backend

    kwargs: dict[str, str] = {}
    if uri:
        kwargs["uri"] = uri
    if user:
        kwargs["user"] = user
    if password:
        kwargs["password"] = password
    try:
        return make_backend("neo4j", **kwargs)
    except Exception as exc:  # noqa: BLE001 — surface as a clear CLI error, not a traceback
        raise click.ClickException(
            f"Could not connect to Neo4j: {exc}\n"
            f"Run `pwngraph doctor` to check connectivity. No docker-compose.yml? "
            f"`pwngraph docker-compose` writes one, then `docker compose up -d`."
        ) from exc


def _load_agent(target: str):
    """Load a LangChain agent from ``path/to/file.py:factory`` or ``module:factory``."""
    if ":" not in target:
        raise click.UsageError(
            "Target must be in the form 'path/to/file.py:factory_function' "
            "or 'module.path:factory_function'."
        )

    locator, factory_name = target.rsplit(":", 1)
    locator_path = Path(locator)

    if locator_path.exists() and locator_path.suffix == ".py":
        # Add the file's own directory so local imports inside the adapter resolve
        parent = str(locator_path.parent.resolve())
        if parent not in sys.path:
            sys.path.insert(0, parent)
        spec = importlib.util.spec_from_file_location("pwngraph_target", str(locator_path))
        if spec is None or spec.loader is None:
            raise click.UsageError(f"Could not load {locator_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules["pwngraph_target"] = module
        spec.loader.exec_module(module)
    else:
        module = importlib.import_module(locator)

    if not hasattr(module, factory_name):
        raise click.UsageError(f"{locator} has no attribute {factory_name!r}")
    factory = getattr(module, factory_name)
    return factory()


if __name__ == "__main__":
    cli()
