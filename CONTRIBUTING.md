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

## Run the test suite

```bash
# Unit tests — no langchain required
pytest -m "not integration"

# Full suite including the lab agent
pytest

# Coverage
pytest --cov=pwngraph --cov-report=html
open htmlcov/index.html
```

## Lint & type check

```bash
ruff check pwngraph tests
black pwngraph tests
mypy pwngraph
```

CI runs all three on every PR.

## What we'd love help with

### High priority

* **More attack-class generators**. v1 ships two; the architecture supports
  many more. Each new class is one file under `pwngraph/fuzzer/` plus a
  route in `fuzzer.py:next_payload`. See `docs/THREAT_MODEL.md` for the v2
  candidates.
* **CrewAI and AutoGen connectors**. Mirror `pwngraph/connector/langchain.py`
  and add a callback bridge equivalent to `langchain_handler.py`.
* **Better tool-argument classification heuristics**. The current `ToolSpec`
  `is_data_sink` / `is_action_sink` predicates are coarse. PRs improving
  classification with embeddings or schema analysis are welcome.

### Medium priority

* **LLM-as-judge confirmation**. Optional second-pass model that grades
  whether a path is actually exploitable, to reduce false positives.
* **Result-set comparison**. Cross-run delta view to highlight regressions
  after a defense ships.
* **More example targets**. CrewAI/LangGraph examples to exercise the
  multi-agent shape.

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
