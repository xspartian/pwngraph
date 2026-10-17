import { Outlet, useLocation, useParams } from "react-router-dom";

import { useTheme } from "../theme/useTheme";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

/**
 * The persistent app frame: top bar + sidebar + main content. A React
 * Router v7 layout route (see App.tsx) — every page renders through
 * <Outlet/> here instead of building its own header/shell.
 *
 * `.app-main`'s scroll behavior mirrors the old `ScanDetailPage`'s
 * `.scan-detail-body`/`.scrolls` split exactly: the attack-graph tab is a
 * fixed-size Sigma.js canvas that must not introduce a page scrollbar,
 * while every other tab (and the scan list) is an ordinary document.
 */
export function AppShell() {
  const { scanId } = useParams<{ scanId?: string }>();
  const { pathname } = useLocation();
  const [theme, toggleTheme] = useTheme();

  const scrolls =
    !scanId ||
    pathname.endsWith("/report") ||
    pathname.endsWith("/findings") ||
    pathname.endsWith("/logs") ||
    pathname.endsWith("/profile");

  return (
    <div className="app-shell">
      <TopBar theme={theme} onToggleTheme={toggleTheme} />
      <div className="app-body">
        <Sidebar scanId={scanId ?? null} />
        <main className={`app-main ${scrolls ? "scrolls" : ""}`}>
          {/* Pages that draw on a <canvas> (GraphExplorer's Sigma instance)
              can't follow the CSS token theme automatically — canvas APIs
              need a literal color, not a custom property lookup. Outlet
              context is how they read the live theme; see
              GraphExplorer.tsx's useOutletContext<CanvasTheme>() call. */}
          <Outlet context={theme} />
        </main>
      </div>
    </div>
  );
}
