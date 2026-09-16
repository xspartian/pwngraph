import type Graph from "graphology";

/** BFS following out-edges — "everything reachable downstream of `start`". */
export function bfsForward(graph: Graph, start: string): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [start];
  while (queue.length) {
    const cur = queue.shift() as string;
    graph.forEachOutNeighbor(cur, (n) => {
      if (!seen.has(n)) {
        seen.add(n);
        queue.push(n);
      }
    });
  }
  return seen;
}

/** BFS following in-edges — "everything that led to `start`". */
export function bfsBackward(graph: Graph, start: string): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [start];
  while (queue.length) {
    const cur = queue.shift() as string;
    graph.forEachInNeighbor(cur, (n) => {
      if (!seen.has(n)) {
        seen.add(n);
        queue.push(n);
      }
    });
  }
  return seen;
}

/** Everything upstream or downstream of a clicked node — the "trace attack
 * path" interaction, ported from the old pyvis UI's trace()/walk(). */
export function tracePath(graph: Graph, nodeId: string): Set<string> {
  const set = new Set<string>([nodeId]);
  bfsForward(graph, nodeId).forEach((n) => set.add(n));
  bfsBackward(graph, nodeId).forEach((n) => set.add(n));
  return set;
}

/**
 * The whole chain a node belongs to — its weakly-connected component, edge
 * direction ignored.
 *
 * Distinct from {@link tracePath}, which follows direction and so returns only
 * what led *to* a node plus what flowed *from* it. For a sink, that is the
 * attack path proper; the rest of the run (a sibling branch off the same tool
 * result, say) is part of the same chain but not on the path. Rendering wants
 * both: the path emphasised, the chain around it still legible.
 */
export function chainOf(graph: Graph, nodeId: string): Set<string> {
  const seen = new Set<string>([nodeId]);
  const queue: string[] = [nodeId];
  while (queue.length) {
    const cur = queue.shift() as string;
    graph.forEachNeighbor(cur, (n) => {
      if (!seen.has(n)) {
        seen.add(n);
        queue.push(n);
      }
    });
  }
  return seen;
}

export interface ChokePoint {
  tool: string;
  count: number;
  totalSinks: number;
  percent: number;
  nodeIds: string[];
}

/**
 * Every tool_call name that sits upstream of at least one dangerous sink,
 * ranked by how many sinks it sits upstream of — "if you had to constrain
 * one capability first, which one closes the most attack chains?" answered
 * for every tool at once, not just the single best one. `findChokePoint`
 * (below) is the top of this list; the old pyvis UI's chokePoint() only ever
 * needed that single answer.
 */
export function rankChokePoints(graph: Graph): ChokePoint[] {
  const sinks = graph.filterNodes((_n, attrs) => attrs.node_type === "dangerous");
  if (sinks.length === 0) return [];

  const counts = new Map<string, number>();
  sinks.forEach((sink) => {
    const upstream = bfsBackward(graph, sink);
    const namesSeen = new Set<string>();
    upstream.forEach((nid) => {
      const attrs = graph.getNodeAttributes(nid);
      if (attrs.node_type === "tool_call" && attrs.name) namesSeen.add(attrs.name as string);
    });
    namesSeen.forEach((name) => counts.set(name, (counts.get(name) ?? 0) + 1));
  });

  const ranked: ChokePoint[] = [];
  counts.forEach((count, tool) => {
    const nodeIds = graph.filterNodes(
      (_n, attrs) => attrs.node_type === "tool_call" && attrs.name === tool,
    );
    ranked.push({
      tool,
      count,
      totalSinks: sinks.length,
      percent: Math.round((count / sinks.length) * 100),
      nodeIds,
    });
  });
  ranked.sort((a, b) => b.count - a.count || a.tool.localeCompare(b.tool));
  return ranked;
}

/** The single best choke point — `rankChokePoints(graph)[0]`, or null on a
 * scan with no dangerous outcomes at all. */
export function findChokePoint(graph: Graph): ChokePoint | null {
  return rankChokePoints(graph)[0] ?? null;
}

/**
 * Every node reachable downstream of any call site named `toolName` — "if
 * this tool were fully compromised, what else did the agent go on to touch
 * during this scan?" Computed directly off the loaded graph so the graph
 * view's own "Blast radius" action needs no round trip; the
 * `/scans/{id}/blast-radius` API endpoint
 * (`pwngraph.attackpath.blast_radius`) answers the same question — for the
 * CLI and any other client that doesn't already have the graph loaded —
 * deduplicated to tool *names* rather than node ids.
 */
export function blastRadiusNodes(graph: Graph, toolName: string): Set<string> {
  const origins = graph.filterNodes(
    (_n, attrs) => attrs.node_type === "tool_call" && attrs.name === toolName,
  );
  const set = new Set<string>();
  origins.forEach((o) => {
    set.add(o);
    bfsForward(graph, o).forEach((n) => set.add(n));
  });
  return set;
}

/** Every node on a path leading to a CRITICAL dangerous outcome —
 * ported from the old UI's criticalOnly(). */
export function criticalSinkAncestors(graph: Graph): Set<string> {
  const sinks = graph.filterNodes(
    (_n, attrs) => attrs.node_type === "dangerous" && attrs.severity === "critical",
  );
  const set = new Set<string>();
  sinks.forEach((s) => {
    set.add(s);
    bfsBackward(graph, s).forEach((n) => set.add(n));
  });
  return set;
}

/** Nodes/edges touched by any adversarial edge or flagged adversarial
 * themselves — ported from the old UI's toggleAttackOnly(). */
export function attackOnlyNodeSet(graph: Graph): Set<string> {
  const set = new Set<string>();
  graph.forEachNode((n, attrs) => {
    if (attrs.is_adversarial) set.add(n);
  });
  graph.forEachEdge((_e, attrs, source, target) => {
    if (attrs.is_adversarial) {
      set.add(source);
      set.add(target);
    }
  });
  return set;
}
