"""``pwngraph`` CLI.

Usage:
    pwngraph scan --target path/to/agent_module.py:build_agent \
                  --attacks all --iterations 25 --out ./out
    pwngraph version
    pwngraph list-attacks
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from pathlib import Path

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


@click.group()
@click.version_option(__version__, prog_name="pwngraph")
def cli() -> None:
    """PwnGraph — dynamic attack graph discovery for AI agent pipelines."""


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
    type=click.Choice([
        "all",
        "indirect_injection",
        "tool_poisoning",
        "prompt_exfiltration",
        "shell_injection",
        "file_read_injection",
        "memory_poisoning",
    ]),
    help="Which attack class(es) to run. 'all' runs all 6.",
)
@click.option(
    "--profile",
    default=None,
    help=(
        "Named preset (quick, full, owasp-llm, paranoid) or path to a profile "
        "YAML. Sets attacks/iterations/trials/baseline-runs. Any flag you pass "
        "explicitly overrides the profile."
    ),
)
@click.option(
    "--iterations",
    default=25,
    show_default=True,
    type=int,
    help="Adversarial iterations per attack class.",
)
@click.option(
    "--baseline-runs",
    default=3,
    show_default=True,
    type=int,
    help="Number of benign baseline runs before fuzzing.",
)
@click.option(
    "--trials",
    default=1,
    show_default=True,
    type=int,
    help=(
        "Re-deliver each payload this many times. >1 turns single observations "
        "into an Attack Success Rate (successes/trials) with a 95% CI — the "
        "honest way to report stochastic LLM behavior."
    ),
)
@click.option(
    "--out",
    default="./pwngraph_out",
    show_default=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Output directory for report.html, attack_graph.html, trace.json.",
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
    "--dry-run",
    is_flag=True,
    default=False,
    help="Enumerate the agent's tool surface and exit without running any attacks.",
)
@click.option("--no-progress", is_flag=True, default=False, help="Disable the progress bar.")
@click.option(
    "--open/--no-open",
    "open_report",
    default=True,
    show_default=True,
    help="Open the interactive attack graph in your browser when the scan finishes.",
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging.")
def scan(
    target: str,
    profile: str | None,
    attacks: str,
    iterations: int,
    baseline_runs: int,
    trials: int,
    out: Path,
    seed: int | None,
    payload: Path | None,
    payload_only: bool,
    input_key: str | None,
    max_calls: int | None,
    dry_run: bool,
    no_progress: bool,
    open_report: bool,
    verbose: bool,
) -> None:
    """Run a PwnGraph scan against a target agent."""
    _setup_logging(verbose)

    # Apply a profile preset. Values only fill in flags the user left at their
    # default — anything passed explicitly on the command line wins.
    if profile is not None:
        prof = _load_profile(profile)
        ctx = click.get_current_context()

        def _from_default(name: str) -> bool:
            return ctx.get_parameter_source(name) == click.core.ParameterSource.DEFAULT

        if "attacks" in prof and _from_default("attacks"):
            attacks = prof["attacks"]
        if "iterations" in prof and _from_default("iterations"):
            iterations = int(prof["iterations"])
        if "trials" in prof and _from_default("trials"):
            trials = int(prof["trials"])
        if "baseline_runs" in prof and _from_default("baseline_runs"):
            baseline_runs = int(prof["baseline_runs"])
        console.print(f"Profile : [green]{prof.get('name', profile)}[/green]")

    console.rule("[bold blue]PwnGraph scan[/bold blue]")
    console.print(f"Target  : [cyan]{target}[/cyan]")
    console.print(f"Attacks : [cyan]{attacks}[/cyan]")
    console.print(
        f"Iters   : [cyan]{iterations}[/cyan] payloads/class × "
        f"[cyan]{trials}[/cyan] trials, [cyan]{baseline_runs}[/cyan] baseline"
    )
    if max_calls:
        console.print(f"Budget  : [yellow]max {max_calls} calls[/yellow]")
    console.print(f"Output  : [cyan]{out}[/cyan]")

    agent = _load_agent(target)
    pg = PwnGraph(agent=agent, seed=seed, input_key=input_key)

    # Load custom payloads if supplied. Pass the agent's tool names so templates
    # declaring `requires_tool` are skipped when the agent lacks that tool.
    custom_payloads = None
    if payload is not None:
        from pwngraph.fuzzer.custom_payload import load_payloads
        agent_tools = {t.name for t in pg.connector.list_tools()}
        all_loaded = load_payloads(payload)
        custom_payloads = [
            p for p in all_loaded
            if not (p.requires_tool and p.requires_tool not in agent_tools)
        ]
        skipped = len(all_loaded) - len(custom_payloads)
        msg = f"Custom  : [magenta]{len(custom_payloads)} payload(s) from {payload}[/magenta]"
        if skipped:
            msg += f" [dim]({skipped} skipped — required tool absent)[/dim]"
        console.print(msg)

    # Dry-run: just enumerate the tool surface and exit.
    if dry_run:
        from pwngraph.preflight import dry_run as do_dry_run
        result = do_dry_run(pg.connector)
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

    effective_attacks = "none" if (payload_only and custom_payloads) else attacks
    paths = pg.scan(
        attacks=effective_attacks,
        iterations=iterations,
        baseline_runs=baseline_runs,
        trials=trials,
        max_calls=max_calls,
        progress=not no_progress,
        custom_payloads=custom_payloads,
    )

    report_path = pg.report(out)
    metrics = pg.metrics()

    table = Table(title="Scan metrics", show_header=False)
    for k, v in metrics.items():
        table.add_row(k, str(v))
    console.print(table)

    _print_asr(pg.asr)
    _print_owasp(pg.owasp_coverage())

    # #13 — single-line risk verdict
    grade = pg.risk_grade()
    grade_color = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
    console.print(Panel(
        f"[{grade_color.get(grade['grade'], 'white')}]"
        f"RISK GRADE: {grade['grade']}  (score {grade['score']}/100)[/]\n"
        f"{grade['interpretation']}\n"
        f"[dim]findings={len(pg.findings)}  "
        f"ASR={metrics.get('attack_success_rate', 0)*100:.0f}%  "
        f"OWASP detected={sum(1 for r in pg.owasp_coverage() if r['status']=='detected')}[/dim]",
        title="Verdict", border_style="blue",
    ))

    if paths:
        console.print(f"\n[bold red]Found {len(paths)} dangerous attack paths[/bold red]")
    else:
        console.print(
            "\n[bold green]No dangerous paths found.[/bold green] "
            "Consider raising --iterations or expanding attack classes."
        )
    graph_path = out / "attack_graph.html"
    console.print(f"\n→ Report: [bold]{report_path}[/bold]")
    console.print(f"→ Graph : [bold]{graph_path}[/bold]")
    console.print(f"→ Trace : [bold]{out / 'trace.json'}[/bold]")

    if open_report:
        _open_in_browser(graph_path)


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

@cli.command()
def doctor() -> None:
    """Check that the environment is ready to run a scan."""
    from pwngraph.preflight import doctor as run_checks, summarize

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
    help=(
        "Agent file to scan. Auto-detected from the current directory when omitted."
    ),
)
def init_cmd(out: Path, target: Path | None) -> None:
    """Generate adapter.py for your agent — just run `pwngraph init`.

    When OPENAI_API_KEY is set, PwnGraph auto-detects your agent file, reads
    the source, and asks GPT-4o-mini to generate a ready-to-scan adapter.py
    with the correct imports and tools populated automatically.

    No flags required:

        export OPENAI_API_KEY=sk-...
        pwngraph init

    Override the detected file:

        pwngraph init --target path/to/my_agent.py
    """
    import os

    console.rule("[bold blue]PwnGraph Init[/bold blue]")

    api_key = os.getenv("OPENAI_API_KEY")

    # ── Resolve the agent file ────────────────────────────────────────────────
    agent_file = target
    if agent_file is None:
        agent_file = _find_agent_file(Path("."))
        if agent_file is not None:
            console.print(f"[green]Detected :[/green] [cyan]{agent_file}[/cyan]")
        else:
            console.print("[yellow]No agent file found in current directory.[/yellow]")

    # ── LLM-powered mode ──────────────────────────────────────────────────────
    if agent_file is not None and api_key:
        console.print(f"[green]Mode     :[/green] LLM-powered")
        console.print()
        ok = _llm_generate_adapter(agent_file, out)
        if ok:
            console.print(f"\n[bold green]Generated:[/bold green] {out}")
            console.print()
            console.print("Next steps:")
            console.print(
                f"  1. [bold cyan]pwngraph scan --target {out}:build_agent --dry-run[/bold cyan]"
                "    ← verify tool count"
            )
            console.print(
                f"  2. [bold cyan]pwngraph scan --target {out}:build_agent --attacks all --out ./out[/bold cyan]"
            )
            console.print()
            console.print("[dim]If --dry-run shows 0 tools, run `pwngraph init --target <file>` and point at the correct agent file.[/dim]")
            return
        console.print("[yellow]LLM generation failed — falling back to template.[/yellow]")
        console.print()

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
        console.print("[yellow]Framework not recognised — generic adapter will be generated.[/yellow]")

    if result.factory_hint:
        console.print(f"[dim]Factory  : {result.factory_hint} (in {result.module_hint})[/dim]")
    console.print()

    _FW_CHOICES = click.Choice([
        "langgraph_react", "langgraph_stategraph",
        "langchain_executor", "langchain_react", "unknown",
    ])
    framework = click.prompt("Framework ", default=result.framework, type=_FW_CHOICES)
    module    = click.prompt("Module    ", default=result.module_hint  or "your_module")
    cls       = click.prompt("Factory   ", default=result.factory_hint or "build_agent")
    input_key = click.prompt("Input key ", default=result.input_key_hint)

    console.print()
    generate_adapter(framework=framework, module=module, cls=cls,
                     input_key=input_key, output_path=out)

    console.print(f"[bold green]Generated:[/bold green] {out}")
    console.print()
    console.print("[dim]Edit the EDIT 1 and EDIT 2 sections in the file, then:[/dim]")
    console.print(f"  [bold cyan]pwngraph scan --target {out}:build_agent --dry-run[/bold cyan]")
    console.print(f"  [bold cyan]pwngraph scan --target {out}:build_agent --attacks all --out ./out[/bold cyan]")


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
        console.print(
            f"[dim]{succ}/{tot} distinct payloads succeeded at least once.[/dim]"
        )


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


_ADAPTER_SYSTEM_PROMPT = """\
You are a PwnGraph adapter generator. PwnGraph is a security testing tool for AI agents.
It needs an adapter.py containing ONE function — build_agent() — that returns a live,
callable agent instance. PwnGraph calls this function to get an agent to attack.

You will receive Python source code for an AI agent you have never seen before.
Your job is to produce a working adapter.py no matter what the agent looks like.

Output ONLY valid Python code. No markdown. No code fences. No explanation.

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


def _find_agent_file(scan_dir: Path) -> Path | None:
    """Return the most likely agent Python file in scan_dir.

    Scores every .py file by how many LLM-agent signals it contains and
    returns the winner. Returns None if no file scores above zero.
    """
    _SIGNALS = [
        "@tool", "build_agent", "create_react_agent", "AgentExecutor",
        "ChatOpenAI", "ChatGoogleGenerativeAI", "ChatGroq", "ChatAnthropic",
        "langgraph", "langchain", "tool_calling_agent",
    ]
    _SKIP_PREFIXES = ("test_", "conftest", "setup", "adapter", "_")

    candidates: list[tuple[int, Path]] = []
    for py_file in sorted(scan_dir.glob("*.py")):
        if any(py_file.name.startswith(p) for p in _SKIP_PREFIXES):
            continue
        try:
            text = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        score = sum(text.count(sig) for sig in _SIGNALS)
        if score > 0:
            candidates.append((score, py_file))

    if not candidates:
        return None
    candidates.sort(key=lambda x: -x[0])
    return candidates[0][1]


def _llm_generate_adapter(source_path: Path, out: Path) -> bool:
    """Use GPT-4o-mini to read source_path and write a pre-filled adapter to out.

    Returns True on success, False if the API key is missing or openai is unavailable.
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

    with console.status(f"[dim]Asking GPT-4o-mini to analyse {source_path.name}…[/dim]"):
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": _ADAPTER_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Generate adapter.py for this agent:\n\n"
                        f"```python\n{source}\n```"
                    ),
                },
            ],
            temperature=0,
        )

    code = resp.choices[0].message.content.strip()
    # Strip markdown fences if the model added them despite the instruction
    if code.startswith("```"):
        lines = code.splitlines()
        start = 1
        end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
        code = "\n".join(lines[start:end])

    # Syntax check before writing
    try:
        compile(code, "<adapter>", "exec")
    except SyntaxError as exc:
        console.print(f"[yellow]⚠ LLM produced invalid syntax ({exc}) — saving anyway, please review.[/yellow]")

    out.write_text(code, encoding="utf-8")
    return True


def _open_in_browser(path: Path) -> None:
    """Open an HTML file in the user's default browser.

    Handles native Linux/macOS/Windows via the stdlib ``webbrowser`` module,
    with a WSL fallback that hands the Windows-translated path to the Windows
    shell (``webbrowser`` is usually a no-op inside WSL).
    """
    import os
    import subprocess
    import webbrowser

    abs_path = path.resolve()

    # WSL detection — webbrowser can't reach a Windows browser from inside WSL.
    is_wsl = "microsoft" in os.uname().release.lower() if hasattr(os, "uname") else False
    if is_wsl:
        try:
            # Translate /mnt/g/... to a Windows path and open with explorer.exe
            win_path = subprocess.check_output(
                ["wslpath", "-w", str(abs_path)], text=True
            ).strip()
            subprocess.Popen(["explorer.exe", win_path], stderr=subprocess.DEVNULL)
            console.print("[dim]Opened attack graph in your browser.[/dim]")
            return
        except Exception:  # noqa: BLE001 — fall through to webbrowser
            pass

    try:
        opened = webbrowser.open(abs_path.as_uri())
        if opened:
            console.print("[dim]Opened attack graph in your browser.[/dim]")
        else:
            console.print(
                f"[dim]Open the graph manually: {abs_path}[/dim]"
            )
    except Exception:  # noqa: BLE001
        console.print(f"[dim]Open the graph manually: {abs_path}[/dim]")


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
