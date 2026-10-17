import Graph from "graphology";

import type { GraphView } from "../api/types";
import { DEFAULT_NODE_SIZE, NODE_SIZES, edgeColor, nodeColor, type CanvasTheme } from "../theme/colors";

/** Horizontal distance between two ranks (one hop along the chain). */
const X_GAP = 92;
/** Vertical distance between two nodes that sit at the same rank. Every node
 * now draws its label permanently (not just on hover), so this has to leave
 * room for that text below each node without the next row overlapping it. */
const Y_GAP = 58;
/** Gap left between neighbouring chains, in the same units. */
const CHAIN_PAD_X = 100;
const CHAIN_PAD_Y = 84;

/**
 * Builds a graphology MultiDirectedGraph from one scan's /graph payload and
 * lays it out — the client-side replacement for vis.js's barnes_hut physics
 * the old pyvis export used. Multi-edge because two events can carry more
 * than one edge between them (e.g. a normal_flow and a tool_manipulation
 * edge both connecting the same pair) — the same reason
 * GraphBackend.edges_between returns a list on the Python side.
 *
 * The layout is deliberately *not* force-directed. A PwnGraph trace is a
 * forest of small directed runs — user input → tool call → tool result →
 * answer, with a dangerous outcome hanging off the end — and that is a
 * sequence, not a cloud. Force layouts render every such run as a rounded
 * blob: technically separated, but with no way to tell where a chain starts,
 * which direction influence flowed, or how far a payload travelled. So each
 * chain is laid out in ranks instead, flowing strictly left → right along
 * edge direction, which is the shape the data actually has.
 *
 * Chains are then packed onto shelves rather than scattered, and ordered so
 * chains containing a dangerous outcome come first. Position carries meaning:
 * the top-left of the canvas is where the attacks are, and reading order —
 * left to right, top to bottom — is severity order.
 */
export function buildGraphology(view: GraphView, theme: CanvasTheme = "dark"): Graph {
  const graph = new Graph({ type: "directed", multi: true });

  view.nodes.forEach((n) => {
    // Colour comes from the local validated palette keyed by node_type, not
    // from the `color` stored on the node — see theme/colors.ts for why
    // (scans predating the palette carry the old hexes). nodeColor() picks
    // the light-safe variant for the couple of identity colors that don't
    // clear contrast on a white canvas (see theme/colors.ts).
    const color = nodeColor(n.node_type, theme);
    graph.addNode(n.id, {
      ...n,
      x: 0,
      y: 0,
      size: NODE_SIZES[n.node_type] ?? DEFAULT_NODE_SIZE,
      color,
      label: n.label,
      baseColor: color,
    });
  });

  view.edges.forEach((e) => {
    if (!graph.hasNode(e.source) || !graph.hasNode(e.target)) return;
    const color = edgeColor(e.edge_type, theme);
    graph.addEdge(e.source, e.target, {
      ...e,
      color,
      baseColor: color,
      size: e.is_adversarial ? 2.5 : 1.4,
      type: "arrow",
    });
  });

  if (graph.order === 0) return graph;

  const chains = weaklyConnectedComponents(graph)
    .map((members) => layoutChain(graph, members))
    .sort(compareChains);

  packChains(chains).forEach(({ chain, x, y }) => {
    chain.positions.forEach((p, id) => {
      graph.setNodeAttribute(id, "x", x + p.x);
      // Negated: sigma's y axis points up, and packing works top-down. Without
      // this the ordering inverts on screen and the dangerous chains — the
      // whole point of the sort — land at the bottom of the canvas.
      graph.setNodeAttribute(id, "y", -(y + p.y));
    });
  });

  return graph;
}

interface Chain {
  members: string[];
  /** Node positions relative to this chain's own top-left corner. */
  positions: Map<string, { x: number; y: number }>;
  width: number;
  height: number;
  hasDangerous: boolean;
}

/** Weakly-connected components (edge direction ignored) via plain BFS over
 * graphology's combined in+out neighbor iterator. */
function weaklyConnectedComponents(graph: Graph): string[][] {
  const seen = new Set<string>();
  const components: string[][] = [];

  graph.forEachNode((start) => {
    if (seen.has(start)) return;
    const component: string[] = [];
    const queue: string[] = [start];
    seen.add(start);
    while (queue.length) {
      const cur = queue.shift() as string;
      component.push(cur);
      graph.forEachNeighbor(cur, (n) => {
        if (!seen.has(n)) {
          seen.add(n);
          queue.push(n);
        }
      });
    }
    components.push(component);
  });

  return components;
}

/**
 * Ranks one chain by longest path from its entry points and lays the ranks
 * out left → right, then returns positions relative to the chain's own
 * bounding box.
 *
 * Longest path rather than BFS depth so a node never sits to the left of
 * something that feeds it: a tool result reachable both directly and via a
 * thought still lands after both.
 */
function layoutChain(graph: Graph, members: string[]): Chain {
  const rank = rankNodes(graph, members);

  const byRank = new Map<number, string[]>();
  members.forEach((id) => {
    const r = rank.get(id) ?? 0;
    const bucket = byRank.get(r);
    if (bucket) bucket.push(id);
    else byRank.set(r, [id]);
  });

  const ranks = [...byRank.keys()].sort((a, b) => a - b);
  const slot = new Map<string, number>();

  // Within a rank, order nodes by the average slot of whatever feeds them.
  // One forward pass is enough to keep a run's edges from crossing — these
  // chains are a few nodes wide at most, not a dense layered DAG.
  ranks.forEach((r) => {
    const bucket = byRank.get(r) as string[];
    const key = new Map<string, number>();
    bucket.forEach((id, i) => {
      let sum = 0;
      let n = 0;
      graph.forEachInNeighbor(id, (p) => {
        const s = slot.get(p);
        if (s !== undefined) {
          sum += s;
          n += 1;
        }
      });
      key.set(id, n ? sum / n : i);
    });
    bucket.sort((a, b) => (key.get(a) as number) - (key.get(b) as number));
    bucket.forEach((id, i) => slot.set(id, i));
  });

  const widest = Math.max(...ranks.map((r) => (byRank.get(r) as string[]).length));
  const positions = new Map<string, { x: number; y: number }>();

  ranks.forEach((r, ri) => {
    const bucket = byRank.get(r) as string[];
    // Each rank is centred on the chain's own mid-line, so a chain reads as a
    // spine with its branches balanced around it.
    const offset = ((widest - bucket.length) / 2) * Y_GAP;
    bucket.forEach((id, i) => {
      positions.set(id, { x: ri * X_GAP, y: offset + i * Y_GAP });
    });
  });

  return {
    members,
    positions,
    width: (ranks.length - 1) * X_GAP,
    height: (widest - 1) * Y_GAP,
    hasDangerous: members.some((id) => graph.getNodeAttribute(id, "node_type") === "dangerous"),
  };
}

/**
 * Longest-path rank per node. Kahn's algorithm over the chain's own induced
 * subgraph; anything left over (a cycle — possible if an agent's output is
 * fed back into it) is placed one step after its deepest settled predecessor
 * so the layout always terminates with every node positioned.
 */
function rankNodes(graph: Graph, members: string[]): Map<string, number> {
  const memberSet = new Set(members);
  const indegree = new Map<string, number>();
  const rank = new Map<string, number>();

  members.forEach((id) => {
    let deg = 0;
    graph.forEachInNeighbor(id, (p) => {
      if (memberSet.has(p) && p !== id) deg += 1;
    });
    indegree.set(id, deg);
  });

  const queue = members.filter((id) => (indegree.get(id) as number) === 0);
  queue.forEach((id) => rank.set(id, 0));

  while (queue.length) {
    const cur = queue.shift() as string;
    const curRank = rank.get(cur) as number;
    graph.forEachOutNeighbor(cur, (n) => {
      if (!memberSet.has(n) || n === cur) return;
      rank.set(n, Math.max(rank.get(n) ?? 0, curRank + 1));
      const left = (indegree.get(n) as number) - 1;
      indegree.set(n, left);
      if (left === 0) queue.push(n);
    });
  }

  members.forEach((id) => {
    if (rank.has(id)) return;
    let best = 0;
    graph.forEachInNeighbor(id, (p) => {
      const r = rank.get(p);
      if (r !== undefined) best = Math.max(best, r + 1);
    });
    rank.set(id, best);
  });

  return rank;
}

/** Dangerous chains first, then the longest — so the eye starts on the
 * attacks and the benign baseline runs settle underneath them. */
function compareChains(a: Chain, b: Chain): number {
  if (a.hasDangerous !== b.hasDangerous) return a.hasDangerous ? -1 : 1;
  if (b.members.length !== a.members.length) return b.members.length - a.members.length;
  return a.members[0].localeCompare(b.members[0]);
}

/** Landscape, to match the shape of the canvas sigma fits the graph into. */
const TARGET_ASPECT = 1.7;

/**
 * Shelf packing: fill a row left → right until the next chain would overflow
 * the target width, then start a new row below the tallest chain in the one
 * just finished.
 *
 * The target width is chosen by trying a whole number of columns and keeping
 * whichever comes out closest to landscape, rather than by deriving one from
 * total area. Chains are long and flat — a single run is wider than it is tall
 * by an order of magnitude — so area maths lands between two column counts and
 * rounds to a tall, narrow canvas that wastes most of the viewport. Comparing
 * the aspect each column count actually produces avoids that.
 */
function packChains(chains: Chain[]): { chain: Chain; x: number; y: number }[] {
  const widest = Math.max(...chains.map((c) => c.width)) + CHAIN_PAD_X;

  let best: { chain: Chain; x: number; y: number }[] | null = null;
  let bestError = Infinity;

  for (let columns = 1; columns <= Math.min(chains.length, 8); columns++) {
    const placed = packToWidth(chains, columns * widest);
    const width = Math.max(...placed.map((p) => p.x + p.chain.width));
    const height = Math.max(...placed.map((p) => p.y + p.chain.height)) || 1;
    // Compared in log space so "twice as wide as wanted" and "half as wide"
    // are penalised equally.
    const error = Math.abs(Math.log(width / height / TARGET_ASPECT));
    if (error < bestError) {
      bestError = error;
      best = placed;
    }
  }

  return best as { chain: Chain; x: number; y: number }[];
}

function packToWidth(
  chains: Chain[],
  targetWidth: number,
): { chain: Chain; x: number; y: number }[] {
  const placed: { chain: Chain; x: number; y: number }[] = [];
  let cursorX = 0;
  let shelfY = 0;
  let shelfHeight = 0;

  chains.forEach((chain) => {
    if (cursorX > 0 && cursorX + chain.width > targetWidth) {
      shelfY += shelfHeight + CHAIN_PAD_Y;
      cursorX = 0;
      shelfHeight = 0;
    }
    placed.push({ chain, x: cursorX, y: shelfY });
    cursorX += chain.width + CHAIN_PAD_X;
    shelfHeight = Math.max(shelfHeight, chain.height);
  });

  return placed;
}
