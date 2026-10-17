import "@xyflow/react/dist/style.css";

import {
  Background,
  BackgroundVariant,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { Bot, Database, FileText, Globe, Mail, Terminal, TriangleAlert, Wrench } from "lucide-react";
import { useMemo } from "react";

import type { ChainHypothesisRow, ToolProfileRow } from "../api/types";

/**
 * A compact, mostly-static topology diagram of the agent and its discovered
 * tools — the "map" that sits above Profile's detail grid/table (which
 * carries the description/sample-output/evidence text a diagram node can't
 * show). Built from the same ScanProfile data as the rest of the tab, not
 * separate fake data. Non-interactive by design (no drag, no scroll-zoom —
 * this sits inside a page that scrolls, so hijacking the wheel would be
 * actively annoying): it's meant to be read at a glance, the way the
 * reference dashboard's own topology widget is.
 */
export function ToolTopology({
  tools,
  chains,
}: {
  tools: ToolProfileRow[];
  chains: ChainHypothesisRow[];
}) {
  const { nodes, edges } = useMemo(() => buildGraph(tools, chains), [tools, chains]);

  if (tools.length === 0) return null;

  return (
    <div className="topology-wrap">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        fitView
        fitViewOptions={{ padding: 0.3, maxZoom: 1.1 }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        panOnScroll={false}
        zoomOnScroll={false}
        zoomOnPinch
        zoomOnDoubleClick={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="var(--border-soft)" />
      </ReactFlow>
    </div>
  );
}

function iconFor(tags: string[]) {
  if (tags.includes("file")) return FileText;
  if (tags.includes("web")) return Globe;
  if (tags.includes("email")) return Mail;
  if (tags.includes("code")) return Terminal;
  if (tags.includes("db")) return Database;
  return Wrench;
}

function AgentNode() {
  return (
    <div className="topology-node topology-agent">
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
      <Bot size={16} />
      <span>Agent</span>
    </div>
  );
}

function ToolNode({ data }: NodeProps) {
  const tool = data.tool as ToolProfileRow;
  const flagged = Boolean(data.flagged);
  const Icon = iconFor(tool.tags);
  const role = tool.is_action_sink ? "action" : tool.is_data_sink ? "data" : "plain";
  return (
    <div className={`topology-node topology-tool topology-tool-${role}`}>
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
      {flagged && <TriangleAlert size={11} className="topology-flag" />}
      <Icon size={13} />
      <span className="mono">{tool.name}</span>
    </div>
  );
}

const NODE_TYPES = { agent: AgentNode, tool: ToolNode };

function buildGraph(
  tools: ToolProfileRow[],
  chains: ChainHypothesisRow[],
): { nodes: Node[]; edges: Edge[] } {
  // Chains only ever run data-sink -> action-sink (see AgentCapabilityMap.build
  // / recon.py's _build_attack_plan). Column tools by role instead of one
  // long strip: it turns every chain edge into a short, mostly-horizontal
  // hop between two columns instead of a zigzag along a single column,
  // which is what actually caused the edge crossings at 5+ tools.
  const rowHeight = 84;
  const dataCol = tools.filter((t) => t.is_data_sink && !t.is_action_sink);
  const actionCol = tools.filter((t) => t.is_action_sink);
  const plainCol = tools.filter((t) => !t.is_data_sink && !t.is_action_sink);

  const columnNodes = (col: ToolProfileRow[], x: number) => {
    const startY = -((col.length - 1) * rowHeight) / 2;
    return col.map((t, i) => ({
      id: t.name,
      type: "tool" as const,
      position: { x, y: startY + i * rowHeight },
      data: {
        tool: t,
        flagged:
          t.looks_outbound ||
          chains.some(
            (c) => c.kind === "confirmed_chain" && (c.source_tool === t.name || c.target_tool === t.name),
          ),
      },
      draggable: false,
    }));
  };

  const nodes: Node[] = [
    { id: "agent", type: "agent", position: { x: 0, y: 0 }, data: {}, draggable: false },
    ...columnNodes(dataCol, 300),
    ...columnNodes(actionCol, 560),
    ...columnNodes(plainCol, 820),
  ];

  const edges: Edge[] = tools.map((t) => ({
    id: `agent-${t.name}`,
    source: "agent",
    target: t.name,
    type: "smoothstep",
    style: { stroke: "var(--border)", strokeWidth: 1.5 },
  }));

  const toolNames = new Set(tools.map((t) => t.name));
  for (const c of chains) {
    if (!toolNames.has(c.source_tool) || !toolNames.has(c.target_tool)) continue;
    const confirmed = c.kind === "confirmed_chain";
    edges.push({
      id: `chain-${c.source_tool}-${c.target_tool}`,
      source: c.source_tool,
      target: c.target_tool,
      type: "bezier",
      animated: confirmed,
      label: `${Math.round(c.confidence * 100)}%`,
      style: {
        stroke: confirmed ? "#d03b3b" : "#6b7785",
        strokeWidth: confirmed ? 2 : 1.5,
        strokeDasharray: confirmed ? undefined : "4 3",
      },
      labelStyle: { fill: confirmed ? "#d03b3b" : "#6b7785", fontSize: 10, fontWeight: 700 },
      labelBgStyle: { fill: "var(--surface)" },
    });
  }

  return { nodes, edges };
}
