import { Route, Routes } from "react-router-dom";

import { AppShell } from "./components/AppShell";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { ScanListPage } from "./pages/ScanListPage";

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<ScanListPage />} />
        {/* Nested tabs (graph/profile/findings/report/logs) route inside. */}
        <Route path="/scans/:scanId/*" element={<ScanDetailPage />} />
      </Route>
    </Routes>
  );
}
