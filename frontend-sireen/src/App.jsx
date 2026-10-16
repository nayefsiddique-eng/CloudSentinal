import ScanHistory from "./pages/ScanHistory";
import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import "./App.css";

import Dashboard from "./pages/Dashboard";
import Findings from "./pages/Findings"
import Resources from "./pages/Resources";
import AuditLogs from "./pages/AuditLogs";
import Remediation from "./pages/Remediation";

function App() {
  return (
    <BrowserRouter>
      <div className="app">

        {/* Sidebar */}
        <aside className="sidebar">
          <div className="logo">
            🛡️ <span>CloudSentinel</span>
          </div>

          <nav>
            <NavLink
  to="/remediation"
  className={({ isActive }) => (isActive ? "active" : "")}
>
  Remediation
</NavLink>
            <NavLink
              to="/"
              end
              className={({ isActive }) =>
                isActive ? "active" : ""
              }
            >
              Dashboard
            </NavLink>

            <NavLink
              to="/findings"
              className={({ isActive }) =>
                isActive ? "active" : ""
              }
            >
              Findings
            </NavLink>

            <NavLink
  to="/scan-history"
  className={({ isActive }) => (isActive ? "active" : "")}
>
  Scan History
</NavLink>
            <NavLink
  to="/resources"
  className={({ isActive }) => (isActive ? "active" : "")}
>
  Resources
</NavLink>
            <NavLink
  to="/audit-logs"
  className={({ isActive }) => (isActive ? "active" : "")}
>
  Audit Logs
</NavLink>
          </nav>

          <div className="sidebar-footer">
            <span>Cloud Security Platform</span>
          </div>
        </aside>

        {/* Page Content */}
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/scan-history" element={<ScanHistory />} />
            <Route path="/resources" element={<Resources />} />
            <Route path="/audit-logs" element={<AuditLogs />} />
            <Route path="/remediation" element={<Remediation />} />
          </Routes>
        </main>

      </div>
    </BrowserRouter>
  );
}

export default App;