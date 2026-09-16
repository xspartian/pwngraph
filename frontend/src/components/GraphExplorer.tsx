import {
  ControlsContainer,
  FullScreenControl,
  SigmaContainer,
  useLoadGraph,
  useRegisterEvents,
  useSigma,
  ZoomControl,
} from "@react-sigma/core";
import "@react-sigma/core/lib/style.css";
import type Graph from "graphology";
import type { Attributes } from "graphology-types";
import type Sigma from "sigma";
import { NodeCircleProgram } from "sigma/rendering";
import type { Settings } from "sigma/settings";
import type { NodeDisplayData, PartialButFor } from "sigma/types";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useOutletContext, useSearchParams } from "react-router-dom";

import { api } from "../api/client";
import type {
  GraphFinding as GraphFindingData,
  GraphNode as GraphNodeData,
  GraphView as GraphViewData,
} from "../api/types";
import { useResource } from "../api/useResource";
import type { ChokePoint } from "../graph/analysis";
import {
  attackOnlyNodeSet,
  blastRadiusNodes,
  chainOf,
  criticalSinkAncestors,
  rankChokePoints,
  tracePath,
} from "../graph/analysis";
import { buildGraphology } from "../graph/buildGraphology";
import {
  edgeColor,
  EDGE_TYPE_LABEL,
  nodeColor,
  NODE_TYPE_LABEL,
  NODE_TYPE_ORDER,
  SEVERITY_COLORS,
  type CanvasTheme,
} from "../theme/colors";
import { EmptyState, SeverityBadge, Spinner } from "./ui";

// Must match styles.css's --bg token for each theme — the canvas "dimmed"
// effect (see GraphInteractions' nodeReducer/edgeReducer below) mixes a
// node/edge's color toward this literal value, and canvas math needs a real
// hex string, not a CSS custom property.
const CANVAS_BG: Record<CanvasTheme, string> = { dark: "#0d1117", light: "#f7f8fa" };

type FilterMode = "significant" | "all" | "attackOnly" | "criticalOnly";
type ViewMode = "graph" | "list";

// Severities that count as worth looking at by default — a LOW/INFO sink is
// almost always a "canary echoed in the final answer, verify manually"
// benign reflection (see BehavioralOracle Signal C), not a real finding, and
// rendering it exactly as red as a CRITICAL one overstates the scan.
const SIGNIFICANT_SEVERITIES = new Set(["critical", "high", "medium"]);

const FILTERS: { mode: FilterMode; label: string; hint: string }[] = [
  {
    mode: "significant",
    label: "Significant",
    hint: "Unique chains rated critical, high, or medium — duplicates from repeated trials collapsed to one. The default view.",
  },
  {
    mode: "all",
    label: "All",
    hint: "Every node recorded in this scan, including benign runs, low/info echoes, and repeated trials",
  },
  {
    mode: "attackOnly",
    label: "Attack paths",
    hint: "Every node touched by an adversarial edge, duplicates included",
  },
  {
    mode: "criticalOnly",
    label: "Critical",
    hint: "Only chains ending in a CRITICAL outcome",
  },
];
// focusCamera distinguishes "take me to this" actions (clicking a node or a
// chain) from live search-as-you-type, which must not yank the camera on
// every keystroke.
type Highlight = { kind: "none" } | { kind: "active"; ids: Set<string>; focusCamera?: boolean };

const DIM_NODE: Record<CanvasTheme, string> = { dark: "#1b2230", light: "#dde1e6" };
const DIM_EDGE: Record<CanvasTheme, string> = { dark: "#171c26", light: "#e5e8ec" };

/** Blend `hex` toward `toward` by `t` (0 = unchanged, 1 = fully `toward`).
 * Used for the mid-tier "same chain, off the attack path" nodes: keeping the
 * hue and dropping the intensity says "related but not the point", where a
 * flat grey would just look like another dimmed node. */
function mix(hex: string, toward: string, t: number): string {
  const parse = (h: string) => [
    parseInt(h.slice(1, 3), 16),
    parseInt(h.slice(3, 5), 16),
    parseInt(h.slice(5, 7), 16),
  ];
  const [r1, g1, b1] = parse(hex);
  const [r2, g2, b2] = parse(toward);
  const c = (a: number, b: number) => Math.round(a + (b - a) * t);
  return `#${[c(r1, r2), c(g1, g2), c(b1, b2)]
    .map((v) => v.toString(16).padStart(2, "0"))
    .join("")}`;
}

/** Node labels are the only text on the canvas, so they get trimmed rather
 * than allowed to run into the neighbouring chain. */
function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/**
 * Draws a node's label centred *underneath* it, and nothing else.
 *
 * This replaces two sigma defaults. Its hover renderer draws a white rounded
 * box behind the label — a bright rectangle on a near-black canvas — and its
 * label renderer writes text off to the right, which in a left-to-right
 * layered layout runs straight into the next node in the chain. Underneath
 * and centred, a label sits in the gap between ranks where nothing else is
 * drawn.
 *
 * Every node's label is always on. Earlier this was gated by zoom level and
 * by hover/selection state — most nodes were unlabelled until you moused
 * over them, which meant the data on the node was invisible by default. The
 * data a node carries is meant to be readable at a glance, not conjured by
 * hovering, so `showText` (set in the node reducer) is now unconditionally
 * true for every visible node and this drawer no longer second-guesses it.
 *
 * Installing it takes a subclass, not a setting: sigma resolves the drawers
 * as `nodeProgram?.drawLabel || defaultDrawNodeLabel`, so a program that
 * ships its own — the circle program does — always wins. `drawLabel` and
 * `drawHover` are public instance properties on that class, so overriding
 * them is supported.
 */
function drawNodeLabel<
  N extends Attributes = Attributes,
  E extends Attributes = Attributes,
  G extends Attributes = Attributes,
>(
  context: CanvasRenderingContext2D,
  data: PartialButFor<NodeDisplayData, "x" | "y" | "size" | "label" | "color">,
  settings: Settings<N, E, G>,
): void {
  const d = data as typeof data & {
    showText?: boolean;
    dimmed?: boolean;
  };
  if (!d.showText || typeof data.label !== "string" || !data.label) return;

  const size = settings.labelSize;
  context.font = `${settings.labelWeight} ${size}px ${settings.labelFont}`;
  context.textAlign = "center";
  const text = truncate(data.label, 22);
  const x = data.x;
  const y = data.y + data.size + size + 1;

  // A dark (or, in light mode, light) outline rather than a filled box: it
  // keeps text readable over edges and neighbouring nodes without stamping
  // an opaque rectangle onto the graph the way the default hover box did.
  // This is a module-level function sigma calls imperatively every frame —
  // reading the theme off the DOM attribute here (rather than threading it
  // in as a prop) is what keeps it live across a theme toggle with no extra
  // plumbing, since sigma redraws continuously regardless.
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  context.lineWidth = 3;
  context.strokeStyle = isLight ? "rgba(247,248,250,0.92)" : "rgba(13,17,23,0.92)";
  context.lineJoin = "round";
  context.strokeText(text, x, y);

  context.fillStyle = d.dimmed ? (isLight ? "#9aa3ad" : "#6e7a89") : isLight ? "#14181f" : "#e6edf3";
  context.fillText(text, x, y);

  // Reset — sigma shares one canvas context across every drawer.
  context.lineWidth = 1;
  context.textAlign = "left";
}

/** The circle node program with both text drawers replaced. Every node
 * renders as a circle, so this is the only program in play. Hover uses the
 * same drawer as the normal label — hovering shouldn't summon a differently
 * styled pill, it should just light the node up. */
class ThemedCircleProgram extends NodeCircleProgram {
  drawLabel = drawNodeLabel;
  drawHover = drawNodeLabel;
}

/**
 * Frames a set of nodes so they all fit on screen with a margin — used both
 * for the initial view and for "take me to this chain".
 *
 * Sigma has no fit helper in this version, and its own default view scales the
 * graph's bounding *square* to the smaller viewport edge with no margin, so a
 * tall graph loads with its last row clipped by the bottom of the canvas.
 * Rather than restate sigma's normalization maths, this measures the target's
 * pixel footprint at the camera's current state and scales the ratio by
 * however far off it is — so it stays correct whatever that maths does.
 */
function fitCameraToNodes(
  sigma: Sigma,
  ids: string[],
  opts: { fill?: number; duration?: number } = {},
): void {
  const fill = opts.fill ?? 0.86;
  const pts = ids
    .map((id) => sigma.getNodeDisplayData(id))
    .filter((p): p is NonNullable<typeof p> => !!p);
  if (!pts.length) return;

  const xs = pts.map((p) => p.x);
  const ys = pts.map((p) => p.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);

  const camera = sigma.getCamera();
  const state = camera.getState();
  const { width, height } = sigma.getDimensions();
  const a = sigma.framedGraphToViewport({ x: minX, y: minY });
  const b = sigma.framedGraphToViewport({ x: maxX, y: maxY });

  const ratio = Math.max(
    0.1, // a single node has no extent of its own to scale to
    (state.ratio * Math.abs(b.x - a.x)) / (width * fill),
    (state.ratio * Math.abs(b.y - a.y)) / (height * fill),
  );
  camera.animate(
    { x: (minX + maxX) / 2, y: (minY + maxY) / 2, ratio },
    { duration: opts.duration ?? 0 },
  );
}

export function GraphExplorer({ scanId }: { scanId: string }) {
  const theme = useOutletContext<CanvasTheme>();
  const { data, error, loading } = useResource<GraphViewData>(() => api.getGraph(scanId), [scanId]);
  const graph = useMemo(() => (data ? buildGraphology(data, theme) : null), [data, theme]);

  // The graph's own `findings` list is already deduplicated by chain shape
  // server-side (see graph_export._findings_from_sinks) — this just narrows
  // it to the severities worth defaulting to. `significantIds` is the node
  // set both the canvas's "Significant" filter and the Findings panel's
  // default view are built from, so the two always agree on what counts.
  const significantFindings = useMemo(
    () =>
      (data?.findings ?? []).filter((f) =>
        SIGNIFICANT_SEVERITIES.has((f.severity || "").toLowerCase()),
      ),
    [data],
  );
  const significantIds = useMemo(() => {
    const set = new Set<string>();
    significantFindings.forEach((f) => f.nodes.forEach((n) => set.add(n)));
    return set;
  }, [significantFindings]);

  const [filterMode, setFilterMode] = useState<FilterMode>("significant");
  const [viewMode, setViewMode] = useState<ViewMode>("graph");
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [highlight, setHighlight] = useState<Highlight>({ kind: "none" });
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [toast, setToast] = useState<string | null>(null);
  // Findings and Choke Points share the same left-hand slot — only one flyout
  // makes sense open at a time, the same way the node inspector owns the
  // right-hand slot alone.
  const [leftPanel, setLeftPanel] = useState<"findings" | "chokepoints" | null>(null);
  const [searchParams, setSearchParams] = useSearchParams();

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    window.setTimeout(() => setToast((t) => (t === msg ? null : t)), 6000);
  }, []);

  // "Significant" is the default filter, but a scan with nothing rated
  // medium or above would otherwise open on a blank canvas — fall back to
  // "All" rather than let the default view look like a loading failure.
  // Runs once per graph load, not on every filterMode change, since the
  // user switching back to "Significant" by hand on an empty scan should
  // stay empty (that's the honest answer), not bounce back to "All" again.
  useEffect(() => {
    if (graph && data && data.nodes.length > 0 && significantIds.size === 0) {
      setFilterMode("all");
      showToast("No critical/high/medium findings in this scan — showing everything.");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph]);

  const runSearch = useCallback(
    (q: string) => {
      setSearchQuery(q);
      if (!graph || !q.trim()) {
        setHighlight({ kind: "none" });
        return;
      }
      const needle = q.trim().toLowerCase();
      const ids = new Set<string>();
      graph.forEachNode((id, attrs) => {
        const hay =
          `${attrs.label ?? ""} ${attrs.name ?? ""} ${attrs.node_type ?? ""}`.toLowerCase();
        if (hay.includes(needle)) ids.add(id);
      });
      setHighlight({ kind: "active", ids, focusCamera: false });
      if (ids.size === 0) showToast(`Nothing matches “${q.trim()}”.`);
    },
    [graph, showToast],
  );

  const traceNode = useCallback(
    (nodeId: string) => {
      if (!graph || !graph.hasNode(nodeId)) return;
      setSelectedNode(nodeId);
      setHighlight({ kind: "active", ids: tracePath(graph, nodeId), focusCamera: true });
    },
    [graph],
  );

  // The findings panel's own node ids come straight from this same /graph
  // payload (GraphView.findings — each entry's `nodes` is already the
  // resolved chain, walked server-side from its DangerousOutcome sink), so
  // "click a finding, land on its chain" needs no extra fetch — unlike the
  // Findings tab/Report page, which have no graph loaded to focus at all
  // and route here via ?finding=<id> instead (see the effect below).
  const openFindingChain = useCallback(
    (nodeIds: string[]) => {
      if (!graph) return;
      const ids = new Set(nodeIds.filter((id) => graph.hasNode(id)));
      if (ids.size === 0) return;
      setViewMode("graph");
      setSelectedNode(null);
      setHighlight({ kind: "active", ids, focusCamera: true });
    },
    [graph],
  );

  // "View attack chain →" on a finding (Findings tab, or the Report page's
  // findings section) lands here as ?finding=<finding_id>. Once the graph
  // has loaded, fetch that finding's chain and focus the camera on it, then
  // drop the param so it doesn't linger in the URL or re-fire on an
  // unrelated re-render. Only depends on [graph, scanId] deliberately: this
  // route only ever mounts fresh when arriving from Findings/Report (a
  // different route), so "graph just became available" is the one moment
  // this needs to run — see traceNode's camera-focus effect below for the
  // same reasoning applied to hover/selection.
  useEffect(() => {
    const findingId = searchParams.get("finding");
    if (!findingId || !graph) return;
    let cancelled = false;
    api
      .getFindingChain(scanId, findingId)
      .then((chain) => {
        if (cancelled) return;
        const ids = new Set(chain.nodes.filter((id) => graph.hasNode(id)));
        if (ids.size === 0) {
          showToast("This finding's attack chain is no longer in the graph.");
          return;
        }
        setHighlight({ kind: "active", ids, focusCamera: true });
      })
      .catch((err) => {
        if (!cancelled) showToast(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (cancelled) return;
        setSearchParams(
          (prev) => {
            const next = new URLSearchParams(prev);
            next.delete("finding");
            return next;
          },
          { replace: true },
        );
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, scanId]);

  // Every tool ranked by how many dangerous sinks it sits upstream of — "if
  // you can only constrain one capability first, which one closes the most
  // chains?" answered for the whole scan at once, shown in the left panel.
  const chokePoints = useMemo(() => (graph ? rankChokePoints(graph) : []), [graph]);

  const focusChokePoint = useCallback(
    (cp: ChokePoint) => {
      if (!graph) return;
      setSelectedNode(null);
      setHighlight({ kind: "active", ids: new Set(cp.nodeIds), focusCamera: true });
      showToast(
        `${cp.tool} sits on ${cp.count} of ${cp.totalSinks} attack ` +
          `path${cp.totalSinks === 1 ? "" : "s"} (${cp.percent}%). Constraining it breaks the most chains.`,
      );
    },
    [graph, showToast],
  );

  // "Critical only" is the one filter that can legitimately empty the canvas,
  // so it reports that instead of silently blanking the view.
  const applyFilter = useCallback(
    (mode: FilterMode) => {
      if (mode === "criticalOnly" && graph && criticalSinkAncestors(graph).size === 0) {
        showToast("No critical-severity paths in this scan.");
        return;
      }
      if (mode === "significant" && significantIds.size === 0) {
        showToast("No critical/high/medium findings in this scan.");
        return;
      }
      setFilterMode((cur) => (cur === mode ? "all" : mode));
    },
    [graph, significantIds, showToast],
  );

  const resetView = useCallback(() => {
    setFilterMode(significantIds.size > 0 ? "significant" : "all");
    setHiddenTypes(new Set());
    setHighlight({ kind: "none" });
    setSearchQuery("");
    setSelectedNode(null);
    setLeftPanel(null);
  }, [significantIds]);

  const toggleType = useCallback((type: string) => {
    setHiddenTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }, []);

  // The list view's row set — same filters the canvas applies (hidden
  // types, attack-only/critical-only, the search box), computed directly
  // off the API payload rather than sigma state so it works without a
  // canvas ever rendering. A screen reader, or anyone who'd rather scan a
  // table than a force-directed layout, gets the same filtered data either
  // view is in.
  const tableRows = useMemo(() => {
    if (!data || !graph) return [];
    let visible: Set<string> | null = null;
    if (filterMode === "significant") visible = significantIds;
    else if (filterMode === "attackOnly") visible = attackOnlyNodeSet(graph);
    else if (filterMode === "criticalOnly") visible = criticalSinkAncestors(graph);
    const needle = searchQuery.trim().toLowerCase();
    return data.nodes.filter((n) => {
      if (hiddenTypes.has(n.node_type)) return false;
      if (visible && !visible.has(n.id)) return false;
      if (needle) {
        const hay = `${n.label ?? ""} ${n.name ?? ""} ${n.node_type ?? ""}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [data, graph, filterMode, hiddenTypes, searchQuery, significantIds]);

  if (loading) return <Spinner label="Loading attack graph…" />;
  if (error || !data || !graph) {
    return <EmptyState title="Failed to load the attack graph" detail={error} />;
  }
  if (data.nodes.length === 0) {
    return <EmptyState title="This scan recorded no graph nodes" />;
  }

  const typeCounts = data.nodes.reduce<Record<string, number>>((acc, n) => {
    acc[n.node_type] = (acc[n.node_type] ?? 0) + 1;
    return acc;
  }, {});
  const selectedAttrs =
    selectedNode && graph.hasNode(selectedNode) ? graph.getNodeAttributes(selectedNode) : null;

  return (
    <div className="graph-shell">
      <div className="graph-toolbar">
        <input
          className="pwn-search"
          placeholder="Search nodes…"
          value={searchQuery}
          onChange={(e) => runSearch(e.target.value)}
        />
        <div className="seg" role="group" aria-label="Filter the graph">
          {FILTERS.map((f) => (
            <button
              key={f.mode}
              className={`seg-btn ${filterMode === f.mode ? "active" : ""}`}
              onClick={() => applyFilter(f.mode)}
              title={f.hint}
            >
              {f.label}
            </button>
          ))}
        </div>
        <button
          className={`pwn-btn ${leftPanel === "chokepoints" ? "active" : ""}`}
          onClick={() => setLeftPanel((p) => (p === "chokepoints" ? null : "chokepoints"))}
          title="Every tool ranked by how many attack paths it sits on"
        >
          Choke points{chokePoints.length ? ` (${chokePoints.length})` : ""}
        </button>
        <button
          className={`pwn-btn ${leftPanel === "findings" ? "active" : ""}`}
          onClick={() => setLeftPanel((p) => (p === "findings" ? null : "findings"))}
          title="Unique critical/high/medium chains — click one to jump to its chain"
        >
          Findings{significantFindings.length ? ` (${significantFindings.length})` : ""}
        </button>
        <div className="seg" role="group" aria-label="Graph or table view">
          <button
            className={`seg-btn ${viewMode === "graph" ? "active" : ""}`}
            onClick={() => setViewMode("graph")}
            title="The attack graph canvas"
          >
            Graph
          </button>
          <button
            className={`seg-btn ${viewMode === "list" ? "active" : ""}`}
            onClick={() => setViewMode("list")}
            title="Every node as a sortable table — for screen readers, copying data out, or just preferring text"
          >
            List
          </button>
        </div>
        <div className="header-spacer" />
        <span className="graph-stats mono">
          {data.nodes.length} nodes · {data.edges.length} edges · {data.findings.length} chains
        </span>
        <button className="pwn-btn" onClick={resetView}>
          Reset
        </button>
      </div>

      <div className="graph-stage">
        {leftPanel === "findings" && (
          <FindingsPanel
            findings={data.findings}
            significantFindings={significantFindings}
            onSelect={(f) => openFindingChain(f.nodes)}
            onClose={() => setLeftPanel(null)}
          />
        )}
        {leftPanel === "chokepoints" && (
          <ChokePointsPanel
            chokePoints={chokePoints}
            onSelect={focusChokePoint}
            onClose={() => setLeftPanel(null)}
          />
        )}
        {viewMode === "graph" ? (
          <div className="graph-canvas-wrap">
            <SigmaContainer
              key={scanId}
              style={{ height: "100%", width: "100%", background: "var(--bg)" }}
              settings={{
                // Draws the label under each node — see drawNodeLabel for why
                // this is a program subclass rather than a setting.
                nodeProgramClasses: { circle: ThemedCircleProgram },
                renderLabels: true,
                labelColor: { color: theme === "light" ? "#14181f" : "#E6EDF3" },
                labelSize: 13,
                labelWeight: "500",
                // The node reducer sets forceLabel on every node, which makes
                // sigma's own density thinning inert — every node's label is
                // always on (see drawNodeLabel), not conjured by hover or zoom.
                // Labels stay put while panning: text that blinks out mid-drag
                // reads as a rendering fault rather than a declutter.
                labelRenderedSizeThreshold: 0,
                hideLabelsOnMove: false,
                defaultEdgeType: "arrow",
                minCameraRatio: 0.04,
                maxCameraRatio: 14,
              }}
            >
              <LoadGraph graph={graph} />
              <GraphInteractions
                filterMode={filterMode}
                significantIds={significantIds}
                hiddenTypes={hiddenTypes}
                highlight={highlight}
                selectedNode={selectedNode}
                onSelectNode={(id) => (id ? traceNode(id) : setSelectedNode(null))}
                theme={theme}
              />
              <ControlsContainer position="bottom-right" className="sigma-controls">
                <ZoomControl />
                <FullScreenControl />
              </ControlsContainer>
            </SigmaContainer>
            <GraphLegend
              typeCounts={typeCounts}
              hiddenTypes={hiddenTypes}
              onToggleType={toggleType}
              theme={theme}
            />
          </div>
        ) : (
          <GraphTable
            rows={tableRows}
            total={data.nodes.length}
            selectedNode={selectedNode}
            onSelectNode={(id) => traceNode(id)}
            theme={theme}
          />
        )}

        {selectedAttrs && (
          <NodeInspector
            attrs={selectedAttrs}
            theme={theme}
            onClose={() => setSelectedNode(null)}
            onCopyId={() => {
              navigator.clipboard?.writeText(selectedNode ?? "");
              showToast(`Copied node id ${selectedNode}`);
            }}
            onBlastRadius={() => {
              const toolName = selectedAttrs.name as string;
              if (!toolName || !graph) return;
              const ids = blastRadiusNodes(graph, toolName);
              const toolsReached = new Set<string>();
              ids.forEach((id) => {
                const a = graph.getNodeAttributes(id);
                if (a.node_type === "tool_call" && a.name && a.name !== toolName) {
                  toolsReached.add(a.name as string);
                }
              });
              setHighlight({ kind: "active", ids, focusCamera: true });
              showToast(
                toolsReached.size
                  ? `If ${toolName} were fully controlled, the agent went on to touch: ${[...toolsReached].join(", ")}`
                  : `${toolName} reached no other tools downstream in this scan.`,
              );
            }}
          />
        )}
      </div>

      {toast && <div className="pwn-toast">{toast}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sigma-side plumbing — must live inside <SigmaContainer> to use its hooks.
// ---------------------------------------------------------------------------

function LoadGraph({ graph }: { graph: Graph }) {
  const loadGraph = useLoadGraph();
  const sigma = useSigma();
  useEffect(() => {
    loadGraph(graph);
    // After the first frame: the fit measures on-screen geometry, which does
    // not exist until sigma has rendered the graph once.
    const frame = requestAnimationFrame(() => fitCameraToNodes(sigma, graph.nodes()));
    return () => cancelAnimationFrame(frame);
  }, [graph, loadGraph, sigma]);
  return null;
}

function GraphInteractions({
  filterMode,
  significantIds,
  hiddenTypes,
  highlight,
  selectedNode,
  onSelectNode,
  theme,
}: {
  filterMode: FilterMode;
  significantIds: Set<string>;
  hiddenTypes: Set<string>;
  highlight: Highlight;
  selectedNode: string | null;
  onSelectNode: (id: string | null) => void;
  theme: CanvasTheme;
}) {
  const sigma = useSigma();
  const registerEvents = useRegisterEvents();
  const [hovered, setHovered] = useState<string | null>(null);

  // Drag support — sigma ships no built-in node dragging, so this wires it
  // from the raw pointer events. Refs rather than state: a drag updates on
  // every pointer move and must not re-render the tree each pixel.
  const draggedNode = useRef<string | null>(null);
  const didMove = useRef(false);

  useEffect(() => {
    registerEvents({
      downNode: (e) => {
        draggedNode.current = e.node;
        didMove.current = false;
        sigma.getGraph().setNodeAttribute(e.node, "highlighted", true);
      },
      mousemovebody: (e) => {
        if (!draggedNode.current) return;
        didMove.current = true;
        const pos = sigma.viewportToGraph(e);
        const g = sigma.getGraph();
        g.setNodeAttribute(draggedNode.current, "x", pos.x);
        g.setNodeAttribute(draggedNode.current, "y", pos.y);
        // Stop the camera panning underneath the node being dragged.
        e.preventSigmaDefault();
        e.original.preventDefault();
        e.original.stopPropagation();
      },
      mouseup: () => {
        if (draggedNode.current) {
          sigma.getGraph().removeNodeAttribute(draggedNode.current, "highlighted");
        }
        draggedNode.current = null;
      },
      clickNode: ({ node }) => {
        // A drag that just ended must not also register as a select.
        if (didMove.current) {
          didMove.current = false;
          return;
        }
        onSelectNode(node);
      },
      clickStage: () => onSelectNode(null),
      enterNode: ({ node }) => setHovered(node),
      leaveNode: () => setHovered(null),
    });
  }, [registerEvents, onSelectNode, sigma]);

  // What the camera is currently framing, so a resize can re-frame the same
  // thing. A ref, not state: nothing renders from it.
  const framed = useRef<string[] | null>(null);

  // Camera focus for "take me to this chain" actions only. A chain fills more
  // of the canvas than the initial overview does — once you have asked for one
  // specific chain, that is the only thing worth reading.
  useEffect(() => {
    if (highlight.kind !== "active" || highlight.ids.size === 0) {
      framed.current = null;
      return;
    }
    framed.current = [...highlight.ids];
    if (!highlight.focusCamera) return;
    fitCameraToNodes(sigma, framed.current, { fill: 0.7, duration: 500 });
    // Keyed on the highlight alone — sigma is stable for the container's life.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [highlight]);

  // Opening the node inspector narrows the canvas, and so does resizing the
  // window. Sigma keeps its camera across a resize, which leaves whatever you
  // were looking at half off-screen — so re-frame it instead.
  //
  // The very first callback is skipped rather than acted on: ResizeObserver
  // always fires once immediately on observe(), often while the container is
  // still mid-layout (a transient near-zero size), and LoadGraph's own initial
  // fit already covers the real first frame. Refitting to that transient size
  // computes a degenerate ratio and leaves the whole graph off-screen.
  useEffect(() => {
    let skippedFirst = false;
    const observer = new ResizeObserver(() => {
      if (!skippedFirst) {
        skippedFirst = true;
        return;
      }
      const { width, height } = sigma.getDimensions();
      if (width < 50 || height < 50) return;
      const ids = framed.current;
      fitCameraToNodes(sigma, ids ?? sigma.getGraph().nodes(), {
        fill: ids ? 0.7 : 0.86,
        duration: 200,
      });
    });
    observer.observe(sigma.getContainer());
    return () => observer.disconnect();
  }, [sigma]);

  // Reducers translate all UI state (filters, highlight, hover, selection)
  // into per-mark render overrides. Doing it here rather than mutating the
  // graph keeps the underlying data pristine, so Reset is a state change
  // rather than a rebuild.
  useEffect(() => {
    const graph = sigma.getGraph();

    let visible: Set<string> | null = null;
    if (filterMode === "significant") visible = significantIds;
    else if (filterMode === "attackOnly") visible = attackOnlyNodeSet(graph);
    else if (filterMode === "criticalOnly") visible = criticalSinkAncestors(graph);

    // Hovering lights up the node's whole chain. A run is only a handful of
    // nodes, and stopping at one hop cut the chain in half visually — the
    // far end of a user → tool → result → answer → DANGER path stayed dark,
    // which is exactly the part you were trying to read.
    let hoverSet: Set<string> | null = null;
    if (hovered && graph.hasNode(hovered)) {
      hoverSet = chainOf(graph, hovered);
    }

    const active = highlight.kind === "active" ? highlight.ids : null;
    const focus = hoverSet ?? active;

    // Everything in the same chain(s) as the focus. Selecting a sink focuses
    // the directed attack path, which legitimately excludes sibling branches
    // of the same run; painting those near-black made a chain look broken
    // mid-way. They render as a muted middle tier instead — visible as
    // context, clearly not the path.
    let context: Set<string> | null = null;
    if (focus && focus.size) {
      context = new Set<string>();
      focus.forEach((id) => {
        if (graph.hasNode(id)) chainOf(graph, id).forEach((n) => context?.add(n));
      });
    }

    sigma.setSetting("nodeReducer", (node, dataIn) => {
      const res = { ...dataIn };
      const type = res.node_type as string;

      if (hiddenTypes.has(type) || (visible && !visible.has(node))) {
        res.hidden = true;
        return res;
      }

      const inFocus = !focus || focus.has(node);
      // Attempted on every node, regardless of sigma's own label-density
      // thinning.
      res.forceLabel = true;
      // Every node's label is always drawn — the data on a node must be
      // readable at a glance, not something you have to hover to reveal.
      res.showText = true;

      if (!inFocus) {
        const inChain = context?.has(node);
        res.color = inChain
          ? mix((res.baseColor as string) ?? DIM_NODE[theme], CANVAS_BG[theme], 0.62)
          : DIM_NODE[theme];
        res.dimmed = true;
        res.zIndex = inChain ? 1 : 0;
        return res;
      }

      res.color = (res.baseColor as string) ?? res.color;
      res.zIndex = focus ? 2 : 1;

      if (node === selectedNode || node === hovered) {
        // Deliberately *not* `highlighted`: sigma re-renders a highlighted
        // node through its WebGL hover layer, on top of the label canvas, so
        // a highlighted node's own text ends up half-covered by the disc.
        res.zIndex = 3;
      }
      return res;
    });

    sigma.setSetting("edgeReducer", (edge, dataIn) => {
      const res = { ...dataIn };
      const [source, target] = graph.extremities(edge);
      const sType = graph.getNodeAttribute(source, "node_type") as string;
      const tType = graph.getNodeAttribute(target, "node_type") as string;

      if (
        hiddenTypes.has(sType) ||
        hiddenTypes.has(tType) ||
        (visible && (!visible.has(source) || !visible.has(target)))
      ) {
        res.hidden = true;
        return res;
      }
      if (focus && (!focus.has(source) || !focus.has(target))) {
        // Same three tiers as the nodes: on the path, elsewhere in the chain,
        // or unrelated.
        const inChain = context?.has(source) && context?.has(target);
        res.color = inChain
          ? mix((res.baseColor as string) ?? DIM_EDGE[theme], CANVAS_BG[theme], 0.66)
          : DIM_EDGE[theme];
        res.zIndex = 0;
      } else if (focus) {
        res.color = (res.baseColor as string) ?? res.color;
        res.zIndex = 1;
      }
      return res;
    });

    sigma.refresh();
  }, [sigma, filterMode, significantIds, hiddenTypes, highlight, selectedNode, hovered, theme]);

  return null;
}

// ---------------------------------------------------------------------------
// Presentational
// ---------------------------------------------------------------------------

/**
 * Every confirmed finding in this scan, as a left-hand flyout — click one to
 * focus its chain on the canvas without leaving the graph. Same findings
 * list the Findings tab shows, but this is for staying put: no navigation,
 * no re-fetch, just "which of these do I want to look at right now."
 */
function FindingsPanel({
  findings,
  significantFindings,
  onSelect,
  onClose,
}: {
  /** Every unique chain, any severity (already deduplicated server-side). */
  findings: GraphFindingData[];
  /** The critical/high/medium subset — what's shown unless "Show all" is on. */
  significantFindings: GraphFindingData[];
  onSelect: (finding: GraphFindingData) => void;
  onClose: () => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const shown = showAll ? findings : significantFindings;
  const lowCount = findings.length - significantFindings.length;

  return (
    <aside className="findings-panel">
      <div className="findings-panel-head">
        <span>
          Findings <span className="report-section-count">{shown.length}</span>
        </span>
        <button className="inspector-close" onClick={onClose} aria-label="Close">
          ×
        </button>
      </div>
      {lowCount > 0 && (
        <label className="findings-panel-toggle">
          <input
            type="checkbox"
            checked={showAll}
            onChange={(e) => setShowAll(e.target.checked)}
          />
          Show all, including {lowCount} low/info
        </label>
      )}
      {shown.length === 0 ? (
        <div className="findings-panel-empty muted">
          {findings.length === 0
            ? "No confirmed findings in this scan."
            : "No critical/high/medium findings — check “Show all” above."}
        </div>
      ) : (
        <ul className="findings-panel-list">
          {shown.map((f) => (
            <li key={f.i}>
              <button className="findings-panel-item" onClick={() => onSelect(f)}>
                <span className="findings-panel-item-top">
                  <SeverityBadge severity={f.severity} />
                  <span className="muted">{f.confidence}</span>
                </span>
                <span className="findings-panel-item-label">{f.label}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </aside>
  );
}

/**
 * Every tool ranked by how many dangerous chains it sits on — "what's the
 * minimum set of controls that breaks the most of this attack graph?"
 * Clicking a row highlights that tool's call sites and reports the same
 * stat as a toast, the same interaction the single-answer "Choke point"
 * button used to give for only the top result.
 */
function ChokePointsPanel({
  chokePoints,
  onSelect,
  onClose,
}: {
  chokePoints: ChokePoint[];
  onSelect: (cp: ChokePoint) => void;
  onClose: () => void;
}) {
  return (
    <aside className="findings-panel">
      <div className="findings-panel-head">
        <span>
          Choke points <span className="report-section-count">{chokePoints.length}</span>
        </span>
        <button className="inspector-close" onClick={onClose} aria-label="Close">
          ×
        </button>
      </div>
      {chokePoints.length === 0 ? (
        <div className="findings-panel-empty muted">No dangerous paths to analyse in this scan.</div>
      ) : (
        <ul className="findings-panel-list">
          {chokePoints.map((cp) => (
            <li key={cp.tool}>
              <button className="findings-panel-item" onClick={() => onSelect(cp)}>
                <span className="findings-panel-item-top">
                  <span className="chokepoint-rank-bar">
                    <span className="chokepoint-rank-fill" style={{ width: `${cp.percent}%` }} />
                  </span>
                  <span className="muted">{cp.percent}%</span>
                </span>
                <span className="findings-panel-item-label mono">{cp.tool}</span>
                <span className="muted">
                  blocks {cp.count} of {cp.totalSinks} path{cp.totalSinks === 1 ? "" : "s"}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </aside>
  );
}

/**
 * The same node set the canvas draws, as a table instead — every value a
 * plain cell, nothing conveyed by position, color alone, or hover. A canvas
 * gives a screen reader nothing at all; this is also just what a reader who
 * wants to scan, sort by eye, or copy data out of the page would rather have.
 * Row click opens the same NodeInspector the graph view uses, so "click a
 * node to read it in full" behaves identically in both views.
 */
function GraphTable({
  rows,
  total,
  selectedNode,
  onSelectNode,
  theme,
}: {
  rows: GraphNodeData[];
  total: number;
  selectedNode: string | null;
  onSelectNode: (id: string) => void;
  theme: CanvasTheme;
}) {
  if (rows.length === 0) {
    return (
      <div className="graph-table-wrap">
        <EmptyState
          title="No nodes match the current filters"
          detail={total > 0 ? "Clear the search box or the type/attack filters to see more." : undefined}
        />
      </div>
    );
  }

  return (
    <div className="graph-table-wrap">
      <table className="data-table graph-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Name</th>
            <th>Adversarial</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Content</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((n) => (
            <tr
              key={n.id}
              className={n.id === selectedNode ? "graph-table-row-selected" : ""}
              onClick={() => onSelectNode(n.id)}
            >
              <td>
                <span className="graph-table-type">
                  <span
                    className="swatch"
                    style={{ background: nodeColor(n.node_type, theme) }}
                  />
                  {NODE_TYPE_LABEL[n.node_type] ?? n.node_type}
                </span>
              </td>
              <td className="mono">{n.name || "—"}</td>
              <td>
                {n.is_adversarial ? (
                  <span className="badge badge-danger">yes</span>
                ) : (
                  <span className="muted">no</span>
                )}
              </td>
              <td>{n.severity ? <SeverityBadge severity={n.severity} /> : <span className="muted">—</span>}</td>
              <td className="muted">{n.confidence || "—"}</td>
              <td className="graph-table-content">{truncate(n.content, 160)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function GraphLegend({
  typeCounts,
  hiddenTypes,
  onToggleType,
  theme,
}: {
  typeCounts: Record<string, number>;
  hiddenTypes: Set<string>;
  onToggleType: (t: string) => void;
  theme: CanvasTheme;
}) {
  return (
    <div className="graph-legend">
      <div className="legend-head">
        Node types <span className="muted">— click to filter</span>
      </div>
      {NODE_TYPE_ORDER.filter((t) => typeCounts[t]).map((t) => (
        <button
          key={t}
          className={`legend-row interactive ${hiddenTypes.has(t) ? "off" : ""}`}
          onClick={() => onToggleType(t)}
        >
          <span className="swatch" style={{ background: nodeColor(t, theme) }} />
          <span className="legend-label">{NODE_TYPE_LABEL[t]}</span>
          <span className="legend-count">{typeCounts[t]}</span>
        </button>
      ))}
      <div className="legend-head legend-head-spaced">Attack edges</div>
      {Object.entries(EDGE_TYPE_LABEL).map(([type, label]) => (
        <div className="legend-row" key={type}>
          <span className="edge-swatch" style={{ background: edgeColor(type, theme) }} />
          <span className="legend-label">{label}</span>
        </div>
      ))}
    </div>
  );
}

function NodeInspector({
  attrs,
  onClose,
  onCopyId,
  onBlastRadius,
  theme,
}: {
  attrs: Record<string, unknown>;
  onClose: () => void;
  onCopyId: () => void;
  onBlastRadius: () => void;
  theme: CanvasTheme;
}) {
  const nodeType = attrs.node_type as string;
  const severity = attrs.severity as string;
  const isToolCall = nodeType === "tool_call" && !!attrs.name;

  return (
    <aside className="node-inspector">
      <div className="inspector-head">
        <button className="inspector-close" onClick={onClose} aria-label="Close">
          ×
        </button>
        <div className="inspector-type">
          <span className="swatch" style={{ background: nodeColor(nodeType, theme) }} />
          {NODE_TYPE_LABEL[nodeType] ?? nodeType}
        </div>
        <div className="inspector-title">
          {(attrs.name as string) || (attrs.label as string) || "node"}
        </div>
      </div>
      <div className="inspector-body">
        <div className="kv">
          <span className="k">Adversarial</span>
          <span className="v">
            <span className={`badge ${attrs.is_adversarial ? "badge-danger" : "badge-muted"}`}>
              {attrs.is_adversarial ? "yes" : "no"}
            </span>
          </span>
        </div>
        {!!severity && (
          <div className="kv">
            <span className="k">Severity</span>
            <span className="v">
              <span
                className="badge"
                style={{ background: SEVERITY_COLORS[severity] ?? "#6b7785" }}
              >
                {severity}
              </span>
            </span>
          </div>
        )}
        {!!attrs.confidence && (
          <div className="kv">
            <span className="k">Confidence</span>
            <span className="v">{attrs.confidence as string}</span>
          </div>
        )}
        {!!attrs.payload_id && (
          <div className="kv">
            <span className="k">Payload</span>
            <span className="v mono">{attrs.payload_id as string}</span>
          </div>
        )}
        {!!attrs.content && (
          <div className="inspector-content">
            <div className="detail-label">Content</div>
            <pre>{attrs.content as string}</pre>
          </div>
        )}
        <div className="inspector-actions">
          <button className="pwn-btn" onClick={onCopyId}>
            Copy node id
          </button>
          {isToolCall && (
            <button className="pwn-btn" onClick={onBlastRadius}>
              Blast radius
            </button>
          )}
        </div>
      </div>
    </aside>
  );
}
