import { ExternalLink, Moon, Search, Sun } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { api } from "../api/client";
import type { ScanSummary } from "../api/types";
import { useResource } from "../api/useResource";
import type { ThemeName } from "../theme/useTheme";

/**
 * The app's persistent top bar — logo, a real global "jump to scan" search
 * (not decorative: filters the actual scan list as you type), the
 * light/dark toggle, and a link back to the project. Rendered once by
 * AppShell, above the sidebar/main split.
 */
export function TopBar({ theme, onToggleTheme }: { theme: ThemeName; onToggleTheme: () => void }) {
  const { data: scans } = useResource<ScanSummary[]>(() => api.listScans(), []);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const boxRef = useRef<HTMLDivElement>(null);

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle || !scans) return [];
    return scans
      .filter((s) => `${s.target_name ?? ""} ${s.target_id ?? ""} ${s.scan_id}`.toLowerCase().includes(needle))
      .slice(0, 8);
  }, [scans, query]);

  function goTo(scanId: string) {
    setQuery("");
    setOpen(false);
    navigate(`/scans/${encodeURIComponent(scanId)}`);
  }

  return (
    <header className="topbar">
      <Link to="/" className="topbar-brand">
        <img src="/logo.png" alt="" className="topbar-logo" />
        Pwn<span className="brand-accent">Graph</span>
      </Link>

      <div className="topbar-search" ref={boxRef}>
        <Search size={15} className="topbar-search-icon" />
        <input
          className="topbar-search-input"
          placeholder="Search scans by target or id…"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => window.setTimeout(() => setOpen(false), 120)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && matches.length > 0) goTo(matches[0].scan_id);
            if (e.key === "Escape") setOpen(false);
          }}
        />
        {open && query.trim() && (
          <div className="topbar-search-dropdown">
            {matches.length === 0 ? (
              <div className="topbar-search-empty">No scans match “{query.trim()}”</div>
            ) : (
              matches.map((s) => (
                <button
                  key={s.scan_id}
                  className="topbar-search-item"
                  onMouseDown={() => goTo(s.scan_id)}
                >
                  <span className="topbar-search-item-target">
                    {s.target_name || s.target_id || "unknown target"}
                  </span>
                  <span className="topbar-search-item-id mono">{s.scan_id}</span>
                </button>
              ))
            )}
          </div>
        )}
      </div>

      <div className="topbar-spacer" />

      <a
        className="topbar-icon-btn"
        href="https://github.com/xspartian/pwngraph"
        target="_blank"
        rel="noreferrer"
        title="PwnGraph on GitHub"
      >
        <ExternalLink size={17} />
      </a>
      <button
        className="topbar-icon-btn"
        onClick={onToggleTheme}
        title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      >
        {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
      </button>
    </header>
  );
}
