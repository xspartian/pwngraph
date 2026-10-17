import type { ReactNode } from "react";

import { SEVERITY_COLORS } from "../theme/colors";

/** A headline number with a label — the right form when a value is a single
 * fact rather than a distribution. Deliberately not a chart. */
export function StatTile({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  accent?: string;
}) {
  return (
    <div className="stat-tile">
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

/** Reserved status colour + the word itself — a severity never travels as
 * colour alone. */
export function SeverityBadge({ severity }: { severity: string }) {
  const s = (severity || "info").toLowerCase();
  return (
    <span className="badge" style={{ background: SEVERITY_COLORS[s] ?? SEVERITY_COLORS.info }}>
      {s}
    </span>
  );
}

/**
 * A horizontal magnitude bar with its Wilson 95% interval drawn as a whisker.
 * The interval is the whole point of reporting ASR — a 60% rate from 5 trials
 * and one from 500 are different claims, and hiding that would overstate the
 * result.
 */
export function AsrBar({
  value,
  low,
  high,
  color = "#3987e5",
}: {
  value: number;
  low?: number;
  high?: number;
  color?: string;
}) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  const lo = low === undefined ? null : Math.max(0, Math.min(1, low)) * 100;
  const hi = high === undefined ? null : Math.max(0, Math.min(1, high)) * 100;

  return (
    <div className="asr-bar" role="img" aria-label={`${pct.toFixed(0)} percent`}>
      <div className="asr-track">
        <div className="asr-fill" style={{ width: `${pct}%`, background: color }} />
        {lo !== null && hi !== null && (
          <div className="asr-ci" style={{ left: `${lo}%`, width: `${Math.max(hi - lo, 0.5)}%` }}>
            <span className="asr-ci-cap" />
            <span className="asr-ci-cap" />
          </div>
        )}
      </div>
    </div>
  );
}

/** A labelled section with a rule — the repeated page scaffolding. */
export function Section({
  title,
  hint,
  children,
  actions,
}: {
  title: string;
  hint?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="section">
      <div className="section-head">
        <div>
          <h2 className="section-title">{title}</h2>
          {hint && <p className="section-hint">{hint}</p>}
        </div>
        {actions && <div className="section-actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export function EmptyState({ title, detail }: { title: string; detail?: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-title">{title}</div>
      {detail && <div className="empty-detail">{detail}</div>}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="pg-status">
      <span className="spinner" /> {label}
    </div>
  );
}
