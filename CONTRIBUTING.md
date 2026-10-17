# Contributing to PwnGraph

Thanks for considering a contribution. PwnGraph is a research tool aimed at
Black Hat MEA 2026 and beyond; contributions that move toward those goals
are very welcome.

## Setup

```bash
git clone https://github.com/xspartian/pwngraph
cd pwngraph
python -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
```

PwnGraph stores every attack graph in Neo4j — there is no in-process
fallback, and the backend contract suite (`tests/test_backend_contract.py`)
needs a reachable instance to run instead of skipping. Bring up the bundled
dev instance before testing:

```bash
docker compose up -d
pwngraph doctor   # confirms Neo4j is actually reachable, not just installed
```

Working on the live viewer (`pwngraph serve`, `pwngraph/api/`, or
`frontend/`)? Install the `serve` extra and see `frontend/README.md` for the
frontend dev workflow (`npm install && npm run dev`, proxied to `pwngraph
serve`'s API):

```bash
pip install -e ".[all]"   # already includes the `serve` extra
cd frontend && npm install && npm run dev
```

Pointing at a different instance for tests: set `NEO4J_TEST_URI` /
`NEO4J_TEST_USER` / `NEO4J_TEST_PASSWORD` (defaults match
`docker-compose.yml`: `bolt://localhost:7687` / `neo4j` / `pwngraph-dev`).

## Run the test suite

No `OPENAI_API_KEY` needed to run the suite: every fuzzer/generator test
injects a fake `LLMClient` (`tests/_fake_llm_client.py`) instead of hitting
the real API — see `pwngraph/fuzzer/llm_generator.py`'s injectable-client
design.

```bash
# Unit tests — no langchain required. Still needs Neo4j reachable: the
# backend contract suite isn't marked `integration`, since it's exercising
# the storage layer directly, not a full agent scan.
pytest -m "not integration"

# Full suite including the lab agent
pytest

# Coverage
pytest --cov=pwngraph --cov-report=html
open htmlcov/index.html
```

If `pytest` behaves differently than expected, confirm it's actually running
under this venv's interpreter and not a system-wide install shadowing it on
`PATH` (`which pytest`, or just always invoke `python -m pytest`).

## Lint & type check

```bash
ruff check pwngraph tests
black pwngraph tests
mypy pwngraph
```

CI runs all three on every PR.

## What we'd love help with

### High priority

* **AutoGen and MCP support**. `pwngraph/connector/base.py`'s `Connector` ABC
  (see `LangChainConnector`/`LangGraphConnector` for the shape) is the
  pattern to follow for a new framework connector — a duck-typed adapter,
  executor-level tracing if the framework has no callback API. MCP is
  broader: tool-manifest scanning, description poisoning, and tool shadowing
  don't map cleanly onto the existing `Connector` shape and need their own
  design pass first.
* **More attack classes**. v1 ships six; the architecture supports many
  more. Every attack class's content is LLM-generated at scan time
  (`pwngraph/fuzzer/llm_generator.py`) — there are no per-class template
  files to add. A new class is a new entry in that module's
  `_CLASS_PROFILES` (technique description, delivery mode, tool-bias rule)
  plus a new `AttackClass` enum member in `pwngraph/fuzzer/payload.py`.
* **Better tool-argument classification heuristics**. The current `ToolSpec`
  `is_data_sink` / `is_action_sink` predicates are coarse. PRs improving
  classification with embeddings or schema analysis are welcome.
* **`pwngraph query` library growth**. `pwngraph/queries.py` is a small,
  curated registry today (`pwngraph query` lists what exists) — more named
  queries are welcome as long as each one is genuinely backend-portable (see
  the module docstring) and comes with tests against `FakeGraphBackend`.

### Medium priority

* **LLM-as-judge confirmation**. Optional second-pass model that grades
  whether a path is actually exploitable, to reduce false positives.
* **More example targets**. LangGraph examples to exercise multi-node/
  multi-step graph shapes.

### Always welcome

* Documentation fixes.
* Type-annotation improvements.
* Test coverage on the GraphBuilder edge-classification logic.

## Pull request expectations

* One logical change per PR.
* Tests for new code paths. Aim for the same coverage level as existing
  modules (mid-80s on the engine).
* Pass the same checks CI runs: `ruff`, `black --check`, `pytest -m "not integration"`.
* Public API changes go in `CHANGELOG.md` and require a brief note in the
  PR description.

## Code style

* `ruff` + `black` are authoritative. The pre-commit hook (when we add one)
  will enforce them automatically.
* Type hints on every public function. Internal helpers can omit them but
  PRs adding annotations are welcome.
* Docstrings: one-line summary, blank line, optional details. Numpy style
  for parameter blocks in larger functions.

## Security

If you find a vulnerability in PwnGraph itself, please email the maintainers
rather than opening a public issue. PwnGraph runs against live AI systems
and a compromised PwnGraph could harm legitimate research and disclosure
work.

## License

By contributing, you agree your contributions will be licensed under the
project's MIT license.
