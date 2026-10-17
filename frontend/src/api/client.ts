import type {
  EvidenceSummary,
  FindingChain,
  FindingRow,
  GraphView,
  LogsResponse,
  NexusStateResponse,
  ScanCompare,
  ScanProfile,
  ScanReport,
  ScanSummary,
} from "./types";

const BASE = "/api";

/** Thrown for a non-2xx response, carrying the status so callers can tell
 * "this scan has no stored report" (404) apart from a real failure. */
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function parseErrorBody(resp: Response): Promise<never> {
  let detail = await resp.text();
  try {
    detail = (JSON.parse(detail) as { detail?: string }).detail ?? detail;
  } catch {
    /* non-JSON error body — use it verbatim */
  }
  throw new ApiError(resp.status, detail || resp.statusText);
}

async function getJSON<T>(path: string): Promise<T> {
  const resp = await fetch(`${BASE}${path}`);
  if (!resp.ok) return parseErrorBody(resp);
  return (await resp.json()) as T;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) return parseErrorBody(resp);
  return (await resp.json()) as T;
}

/** URLs for the export routes — plain downloadable links (Content-Disposition:
 * attachment), not fetched through getJSON, so a plain <a href> triggers the
 * browser's native save flow. */
export function exportUrl(scanId: string, kind: "graph.json" | "findings.sarif" | "poc.zip") {
  return `${BASE}/scans/${encodeURIComponent(scanId)}/export/${kind}`;
}

export const api = {
  listScans: () => getJSON<ScanSummary[]>("/scans"),

  getGraph: (scanId: string) => getJSON<GraphView>(`/scans/${encodeURIComponent(scanId)}/graph`),

  compareScans: (scanId: string, against: string) =>
    getJSON<ScanCompare>(
      `/scans/${encodeURIComponent(scanId)}/compare?against=${encodeURIComponent(against)}`,
    ),

  setFindingTriage: (scanId: string, findingId: string, status: string, note?: string) =>
    postJSON<{ finding_id: string; status: string; note: string | null }>(
      `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/triage`,
      { status, note },
    ),

  getFindingChain: (scanId: string, findingId: string) =>
    getJSON<FindingChain>(
      `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/chain`,
    ),

  /** Dispatches through pwngraph.queries.QUERY_REGISTRY — any query name
   * registered there works here with no client-side change needed. */
  runQuery: (scanId: string, name: string) =>
    getJSON<Record<string, unknown>[]>(
      `/scans/${encodeURIComponent(scanId)}/query/${encodeURIComponent(name)}`,
    ),

  getFindings: (scanId: string, opts?: { confidence?: string; exfil?: boolean }) => {
    const params = new URLSearchParams();
    if (opts?.confidence) params.set("confidence", opts.confidence);
    if (opts?.exfil) params.set("exfil", "true");
    const qs = params.toString();
    return getJSON<FindingRow[]>(
      `/scans/${encodeURIComponent(scanId)}/findings${qs ? `?${qs}` : ""}`,
    );
  },

  getEvidence: (scanId: string) =>
    getJSON<EvidenceSummary>(`/scans/${encodeURIComponent(scanId)}/evidence`),

  getReport: (scanId: string) =>
    getJSON<ScanReport>(`/scans/${encodeURIComponent(scanId)}/report`),

  /** The raw execution log — every probe, in the order it actually ran. */
  getLogs: (scanId: string) => getJSON<LogsResponse>(`/scans/${encodeURIComponent(scanId)}/logs`),

  /** NEXUS's own decision history for this scan. 404s (via ApiError.status)
   * for a static-mode scan or one that predates this feature — callers
   * should treat that as "no NEXUS data," not a failure. */
  getNexusState: (scanId: string) =>
    getJSON<NexusStateResponse>(`/scans/${encodeURIComponent(scanId)}/nexus`),

  /** Recon's pre-attack profile for this scan. 404s (via ApiError.status)
   * for a scan run with recon disabled or one that predates this feature —
   * callers should treat that as "no profile," not a failure. */
  getProfile: (scanId: string) =>
    getJSON<ScanProfile>(`/scans/${encodeURIComponent(scanId)}/profile`),
};
