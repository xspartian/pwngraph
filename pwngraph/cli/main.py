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
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
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
    help=(
        "Adaptive probes to send. The scan sends exactly this many (on top of the "
        "baseline and recon runs) unless --early-stop, --max-calls, or a blocked/failed "
        "payload stops it sooner — the summary says which."
    ),
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
    "--exhaustive/--early-stop",
    default=True,
    show_default=True,
    help=(
        "--exhaustive (default) spends the whole --budget, giving every class a real, "
        "multi-attempt shot. --early-stop lets NEXUS stop once every class and tool has "
        "one attempt and confidence is high — cheaper, but a class that failed its one "
        "probe is reported untested beyond that single try."
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
        + ("" if exhaustive else "  [yellow]early-stop[/yellow]")
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
    from pwngraph.core import TargetUnavailableError

    try:
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
    except TargetUnavailableError as exc:
        raise click.ClickException(str(exc)) from exc

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
        sent = f"{ns.iteration}/{ns.budget}"
        if ns.iteration < ns.budget:
            sent += f"  [yellow](stopped early: {pg.probe_stop_reason or ns.status.value})[/yellow]"
        nexus_table.add_row("probes sent", sent)
        tries = ns.attempts_per_class()
        nexus_table.add_row(
            "successful_techniques",
            ", ".join(f"{c} ({tries.get(c, 0)} tries)" for c in ns.successful_techniques) or "none",
        )
        # "Failed" overclaims after a try or two — an LLM attack that missed
        # once can land on the next attempt. Say what was actually observed.
        nexus_table.add_row(
            "not_reproduced",
            ", ".join(f"{c} ({tries.get(c, 0)} tries)" for c in ns.failed_techniques) or "none",
        )
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
@click.option("--exhaustive/--early-stop", default=True, show_default=True)
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
    from pwngraph.core import TargetUnavailableError

    try:
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
    except TargetUnavailableError as exc:
        raise click.ClickException(str(exc)) from exc
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
    if grade_regressed and before_grade is not None:
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
    else, and open the viewer once as http://HOST:PORT/?token=TOKEN — that
    sets a cookie the viewer's own API calls use.
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
        console.print(
            "[dim]API token required on every /api/* request — open the viewer "
            f"once as http://{host}:{port}/?token=<token>[/dim]"
        )
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
    help="Hint: the file that defines the agent. The AI starts its exploration there.",
)
@click.option(
    "--model",
    default=None,
    envvar="PWNGRAPH_INIT_MODEL",
    help="OpenAI model that builds the adapter (default: gpt-4.1; env PWNGRAPH_INIT_MODEL).",
)
@click.option(
    "--max-steps",
    default=40,
    show_default=True,
    type=click.IntRange(5, 200),
    help="Exploration/validation steps the AI may take.",
)
@click.option(
    "--timeout",
    default=180,
    show_default=True,
    type=click.IntRange(10, 1800),
    help="Seconds allowed for each adapter validation run (imports + build_agent()).",
)
def init_cmd(
    path: Path,
    out: Path,
    target: Path | None,
    model: str | None,
    max_steps: int,
    timeout: int,
) -> None:
    """Generate adapter.py for any LangChain / LangGraph / plain-Python agent repo.

    Run it from the root of the agent's repository:

        export OPENAI_API_KEY=sk-...
        pwngraph init

    An AI agent explores the repository (file tree, langgraph.json,
    pyproject, the code that builds the agent and its tools), writes
    adapter.py, and actually runs it — import, build_agent(), tool
    enumeration — fixing and re-running until it loads the repository's REAL
    agent with its REAL tools. Adapters that stub tools or don't import the
    repository are rejected. If something only you can fix blocks it (a
    missing dependency or API key), it stops and prints the exact command.

    Validation imports and runs the target's code in a subprocess, exactly as
    a scan will — only run init on code you trust enough to scan.

    Without OPENAI_API_KEY, a static (no-LLM) generator handles simple
    single-file agents.
    """
    import os

    console.rule("[bold blue]PwnGraph Init[/bold blue]")

    root = (path if path.is_dir() else path.parent).resolve()
    hint = target or (path if path.is_file() else None)
    if hint is not None and root not in hint.resolve().parents:
        root = hint.resolve().parent

    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        _ai_init(root, out, hint, model, max_steps, timeout, api_key)
        return

    console.print(
        "[yellow]OPENAI_API_KEY not set — using the static generator, which only handles "
        "simple single-file agents.[/yellow]\n"
        "[dim]export OPENAI_API_KEY=<key> and re-run for AI-driven generation that works "
        "on full repositories.[/dim]\n"
    )
    _static_init(root, out, hint)


def _ai_init(
    root: Path,
    out: Path,
    hint: Path | None,
    model: str | None,
    max_steps: int,
    timeout: int,
    api_key: str,
) -> None:
    from pwngraph.initagent import DEFAULT_MODEL, build_adapter

    try:
        from openai import OpenAI
    except ImportError as exc:
        raise click.ClickException("the openai package is required: pip install openai") from exc

    model = model or DEFAULT_MODEL
    console.print(f"[green]Repo     :[/green] {root}")
    if hint is not None:
        console.print(f"[green]Hint     :[/green] {hint}")
    console.print(f"[green]Mode     :[/green] AI agent ({model}) — explore, write, run, fix")
    console.print("[dim]Validation runs the target's code in a subprocess, as a scan will.[/dim]\n")

    styles = {
        "explore": ("dim", "  ·"),
        "validate": ("cyan", "  ▶ validating adapter"),
        "ok": ("bold green", "  ✓ loaded —"),
        "fail": ("yellow", "  ✗"),
        "info": ("dim", "  ·"),
    }

    def on_event(kind: str, text: str) -> None:
        if kind == "think":
            return
        style, prefix = styles.get(kind, ("dim", "  ·"))
        console.print(f"[{style}]{prefix} {escape(text)}[/{style}]")

    result = build_adapter(
        root,
        out,
        OpenAI(api_key=api_key),
        model=model,
        hint_file=hint,
        max_steps=max_steps,
        timeout=timeout,
        on_event=on_event,
    )
    console.print()

    if not result.ok:
        if result.blocker:
            console.print(f"[bold red]Blocked:[/bold red] {escape(result.blocker)}")
            if result.user_action:
                console.print(f"[bold]Fix:[/bold] {escape(result.user_action)}")
            console.print("[dim]Then re-run `pwngraph init`.[/dim]")
        else:
            console.print(
                f"[bold red]Could not build a working adapter[/bold red] "
                f"after {result.steps} steps / {result.validations} validation runs."
            )
            if result.error:
                tail = "\n".join(result.error.strip().splitlines()[-8:])
                console.print(f"[dim]{escape(tail)}[/dim]")
            console.print(
                "[dim]Try `--target <file that builds the agent>`, a stronger `--model`, "
                "or more `--max-steps`.[/dim]"
            )
        if result.failed_attempt is not None:
            console.print(f"[dim]Last attempt saved to {result.failed_attempt}[/dim]")
        raise SystemExit(1)

    table = Table(title=f"Agent: {result.agent_type}", show_lines=False)
    table.add_column("Tool")
    table.add_column("Defined in")
    table.add_column("Side effects", justify="center")
    for t in result.tools:
        table.add_row(
            t["name"],
            t.get("origin", ""),
            "[red]yes[/red]" if t.get("action_sink") else "",
        )
    console.print(table)
    console.print(
        f"\n[bold green]Generated:[/bold green] {out}  "
        f"[dim]({result.steps} steps, {result.validations} validation runs)[/dim]"
    )
    if any(t.get("action_sink") for t in result.tools):
        console.print(
            "[yellow]Tools marked with side effects run for real during a scan — "
            "point them at a sandbox or mock them first.[/yellow]"
        )
    budget = max(25, len(result.tools) * 3)
    console.print("\nNext steps:")
    console.print(f"  1. [bold cyan]pwngraph scan --target {out}:build_agent --dry-run[/bold cyan]")
    console.print(
        f"  2. [bold cyan]pwngraph scan --target {out}:build_agent --attacks all "
        f"--budget {budget} --authorized --out ./out[/bold cyan]"
    )


def _static_init(root: Path, out: Path, hint: Path | None) -> None:
    """No-LLM fallback: AST read of one file, else the interactive template."""
    agent_file = hint or _find_agent_file(root)
    if agent_file is not None:
        console.print(f"[green]Detected :[/green] [cyan]{agent_file}[/cyan]")
        from pwngraph.scaffold import analyze_plain_agent, generate_plain_adapter

        analysis = analyze_plain_agent(agent_file)
        if analysis.tools:
            console.print(f"[green]Tools    :[/green] {', '.join(n for n, _ in analysis.tools)}")
        if analysis.is_usable:
            generate_plain_adapter(
                module=agent_file.stem,
                entry_function=analysis.entry_function or "",
                tools=analysis.tools,
                tools_dict_name=analysis.tools_dict_name,
                output_path=out,
            )
            budget = _suggested_budget(analysis)
            console.print(f"[bold green]Generated:[/bold green] {out}")
            console.print(
                "[dim]Verify _ENTRY_FUNCTION and _TOOL_DESCRIPTIONS at the top of the "
                "file match your agent, then:[/dim]"
            )
            console.print(
                f"  [bold cyan]pwngraph scan --target {out}:build_agent --dry-run[/bold cyan]"
            )
            console.print(
                f"  [bold cyan]pwngraph scan --target {out}:build_agent --attacks all "
                f"--budget {budget} --authorized --out ./out[/bold cyan]"
            )
            return
    else:
        console.print(f"[yellow]No agent file found under {root}.[/yellow]")

    from pwngraph.scaffold import detect_project, generate_adapter

    with console.status("[dim]Scanning project...[/dim]"):
        result = detect_project(root)

    if result.framework != "unknown":
        console.print(f"[green]Framework:[/green] {result.framework.replace('_', ' ').title()}")
    else:
        console.print(
            "[yellow]Framework not recognised — generic adapter will be generated.[/yellow]"
        )
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
        table.add_row(str(item.rank), item.attack_class, item.target_tool or "—", item.rationale)
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


_AGENT_FILE_SKIP_DIRS = {
    "venv",
    ".venv",
    "__pycache__",
    ".git",
    "node_modules",
    "dist",
    "build",
    ".tox",
    ".pytest_cache",
    "site-packages",
}
_AGENT_FILE_SKIP_PREFIXES = ("test_", "conftest", "setup", "adapter", "_")

# Keyword shortlist — cheap and fast, but inherently incomplete (it can only
# name providers/frameworks we thought of). It's a first pass, not the source
# of truth: any file it misses still gets a real chance via the structural
# fallback below, which reads actual code shape instead of matching strings.
_AGENT_KEYWORD_SIGNALS = [
    "@tool",
    "build_agent",
    "create_react_agent",
    "AgentExecutor",
    "ChatOpenAI",
    "ChatGoogleGenerativeAI",
    "ChatGroq",
    "ChatAnthropic",
    "langgraph",
    "langchain",
    "tool_calling_agent",
    "chat.completions.create",
    "client.chat.completions",
    "openai.OpenAI",
    "anthropic.Anthropic",
    "tool_calls",
    "function_call",
    "TOOL_SCHEMAS",
    "SYSTEM_PROMPT",
    '"role": "system"',
    "'role': 'system'",
]


def _candidate_py_files(scan_dir: Path) -> list[Path]:
    return [
        f
        for f in sorted(scan_dir.rglob("*.py"))
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
