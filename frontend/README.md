# PwnGraph frontend

The live graph/findings/evidence viewer `pwngraph serve` serves — React +
TypeScript, Sigma.js for rendering, Graphology as the client-side graph
model. Reads only through the FastAPI backend in `../pwngraph/api/`, which
in turn reads only through the `GraphBackend` ABC (Neo4j). Nothing here
talks to Neo4j directly.

## Develop

```bash
npm install
npm run dev        # http://localhost:5173, proxies /api to :8000
```

Run `pwngraph serve` (from the repo's Python venv) alongside this so the dev
server has a real API to talk to:

```bash
pwngraph serve      # http://127.0.0.1:8000 — API (+ any previously built SPA)
```

## Build for `pwngraph serve`

```bash
npm run build:pwngraph
```

Builds the SPA (`npm run build` → `dist/`) and copies it into
`../pwngraph/api/static/`, where `pwngraph serve` looks for a built
frontend to mount alongside the API. That directory is git-ignored and not
part of source — rebuild it after any frontend change you want `pwngraph
serve` to pick up. A packaged wheel ships whatever is there at build time
(see `[tool.setuptools.package-data]` in `pyproject.toml`).

## Structure

- `src/api/` — typed fetch client (`client.ts`) and hand-written response
  types (`types.ts`) mirroring `pwngraph/api/schemas.py`.
- `src/theme/` — `colors.ts` (the validated node/edge/severity/grade palette,
  shared with `pwngraph/types.py`) and `useTheme.ts` (the persisted
  light/dark toggle — `data-theme` on `<html>` + `localStorage`).
- `src/graph/` — `buildGraphology.ts` (JSON → `graphology.Graph`, theme-aware
  node/edge colors) and `analysis.ts` (BFS/trace/choke-point/critical-only
  helpers).
- `src/components/AppShell.tsx` — the persistent layout route (top bar +
  sidebar + `<Outlet/>`) every page renders through; see `App.tsx`.
  `TopBar.tsx` (logo, cross-scan search, theme toggle) and `Sidebar.tsx`
  (global nav, or the current scan's identity + 5 tabs) are its two halves.
- `src/components/GraphExplorer.tsx` — the Sigma.js canvas, toolbar, node
  inspector, and legend/toast for the Attack graph tab.
- `src/report/` — one component per scan tab's content (`Profile.tsx`,
  `Findings.tsx`, `Logs.tsx`, `Summary.tsx`/`Evidence.tsx`/`Compare.tsx`/
  `Queries.tsx` under the Report tab), plus `ToolTopology.tsx` (the
  `@xyflow/react` agent/tool-chain diagram on the Profile tab).
- `src/pages/` — thin per-tab wrappers (`ScanListPage`, `ScanDetailPage`'s
  nested routes, `ProfilePage`, `FindingsPage`, `LogsPage`, `ReportPage`)
  that just wire a `scanId` into the matching `src/report/` component.
