// Mirrors pwngraph/types.py's _NODE_COLORS / _NODE_SHAPES and the severity
// status palette. See that module for the validation rationale: the three
// chromatic identity hues plus the reserved critical red clear the lightness
// band, chroma floor, normal-vision separation floor, and 3:1 contrast against
// this canvas, with the worst CVD pair inside the band permitted alongside
// secondary encoding (per-type shape + direct labels + a visible legend).
//
// The renderer derives node colour from `node_type` through this map rather
// than trusting the `color` property stored on the node in Neo4j: a scan run
// before this palette landed carries the old hexes, and rendering both from
// one source keeps every scan visually consistent.

export const NODE_COLORS: Record<string, string> = {
  user_input: "#199e70", // aqua — attacker-controlled entry point
  tool_call: "#3987e5", // blue — the agent invoking a tool
  tool_result: "#c98500", // yellow — data returning into context
  agent_thought: "#6b7785", // neutral, recessive
  final_answer: "#aab4c0", // neutral, light
  dangerous: "#d03b3b", // reserved status:critical
};

export const NODE_TYPE_LABEL: Record<string, string> = {
  user_input: "User Input",
  tool_call: "Tool Call",
  tool_result: "Tool Result",
  agent_thought: "LLM Thought",
  final_answer: "Final Answer",
  dangerous: "Dangerous Outcome",
};

// Every node draws as a plain circle — no glyph, no per-type shape. Size is
// the one differentiator: the dangerous-outcome sink is larger so a chain's
// payoff reads first. Type is carried by colour, the legend, and the label.
export const NODE_SIZES: Record<string, number> = {
  dangerous: 13,
};
export const DEFAULT_NODE_SIZE = 9;

export const NODE_TYPE_ORDER = [
  "user_input",
  "tool_call",
  "tool_result",
  "agent_thought",
  "final_answer",
  "dangerous",
] as const;

// Edge colours encode *how* influence flowed. normal_flow is deliberately a
// recessive neutral so the adversarial edges are what the eye lands on — but
// recessive still has to clear the 3:1 contrast floor a thin graphical line
// needs against the #0D1117 canvas to read as a line at all, not a gap.
// #39414d measured ~1.8:1 there (invisible in practice); #6b7785 — the same
// validated neutral NodeType.AGENT_THOUGHT already uses (see types.py) —
// clears ~4.2:1 while still sitting well below the adversarial hues' chroma.
export const EDGE_COLORS: Record<string, string> = {
  normal_flow: "#6b7785",
  direct_injection: "#d03b3b",
  context_poisoning: "#9085e9",
  tool_manipulation: "#d95926",
  data_exfil: "#d55181",
};

// The graph canvas now follows the light/dark toggle (it used to be forced
// dark regardless of app theme, which read as broken once the rest of the
// chrome went light). Most identity colors above are saturated enough to
// clear a 3:1 contrast floor on white too — only these two don't:
// `final_answer` (#aab4c0) is ~1.9:1 on white, and `context_poisoning`
// (#9085e9) is ~2.5:1, both validated only against the dark canvas. Deepen
// just these for light mode rather than re-deriving a whole second palette.
export const NODE_COLORS_LIGHT: Partial<Record<string, string>> = {
  final_answer: "#6b7785",
};
export const EDGE_COLORS_LIGHT: Partial<Record<string, string>> = {
  context_poisoning: "#6c5ce7",
};

export type CanvasTheme = "dark" | "light";

export function nodeColor(nodeType: string, theme: CanvasTheme): string {
  if (theme === "light" && NODE_COLORS_LIGHT[nodeType]) return NODE_COLORS_LIGHT[nodeType]!;
  return NODE_COLORS[nodeType] ?? "#6b7785";
}

export function edgeColor(edgeType: string, theme: CanvasTheme): string {
  const key = EDGE_COLORS[edgeType] !== undefined ? edgeType : "normal_flow";
  if (theme === "light" && EDGE_COLORS_LIGHT[key]) return EDGE_COLORS_LIGHT[key]!;
  return EDGE_COLORS[key];
}

export const EDGE_TYPE_LABEL: Record<string, string> = {
  direct_injection: "Direct Injection",
  context_poisoning: "Context Poisoning",
  tool_manipulation: "Tool Manipulation",
  data_exfil: "Data Exfil",
};

// Reserved status palette — never reused as a series/identity colour, and
// always shipped beside a text label rather than carrying meaning alone.
export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#d03b3b",
  high: "#ec835a",
  medium: "#fab219",
  low: "#0ca30c",
  info: "#6b7785",
};

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

// Risk grade A–F maps onto the same reserved status ramp: A/B are healthy,
// C is a warning, D/F are serious/critical.
export const GRADE_COLORS: Record<string, string> = {
  A: "#0ca30c",
  B: "#0ca30c",
  C: "#fab219",
  D: "#ec835a",
  F: "#d03b3b",
};

export const THEME = {
  bg: "#0D1117",
  panel: "#161b22",
  panelRaised: "#1c2230",
  border: "#2b3340",
  text: "#E6EDF3",
  muted: "#8b949e",
  accent: "#3987e5",
  danger: "#d03b3b",
} as const;
