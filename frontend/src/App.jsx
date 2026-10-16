import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldAlert,
  History,
  Cloud,
  ScrollText,
  Wrench,
  ShieldCheck,
  ChevronRight,
} from "lucide-react";
import "./App.css";

import Dashboard from "./pages/Dashboard";
import Findings from "./pages/Findings";
import ScanHistory from "./pages/ScanHistory";
import Resources from "./pages/Resources";
import AuditLogs from "./pages/AuditLogs";
import Remediation from "./pages/Remediation";

const navigation = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/findings", label: "Findings", icon: ShieldAlert },
  { to: "/scan-history", label: "Scan History", icon: History },
  { to: "/resources", label: "Resources", icon: Cloud },
  { to: "/audit-logs", label: "Audit Logs", icon: ScrollText },
  { to: "/remediation", label: "Remediation", icon: Wrench },
];

function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <aside className="sidebar">
          <NavLink to="/" className="brand" aria-label="CloudSentinel home">
            <span className="brand-mark"><ShieldCheck size={23} strokeWidth={2.2} /></span>
            <span className="brand-copy">
              <strong>CloudSentinel</strong>
              <small>SECURITY COMMAND</small>
            </span>
          </NavLink>

          <div className="nav-label">WORKSPACE</div>
          <nav className="primary-nav" aria-label="Main navigation">
            {navigation.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
              >
                <Icon size={18} strokeWidth={1.8} />
                <span>{label}</span>
                <ChevronRight className="nav-chevron" size={15} />
              </NavLink>
            ))}
          </nav>

          <div className="sidebar-bottom">
            <div className="connection-indicator"><span /> API workspace</div>
            <div className="sidebar-footer">Cloud security posture<br />monitoring platform</div>
            <div className="sidebar-version">CLOUDSENTINEL <span>•</span> BETA</div>
          </div>
        </aside>

        <main className="main-content">
          <div className="topbar">
            <div className="topbar-breadcrumb"><span>Workspace</span><span className="breadcrumb-slash">/</span><strong>Cloud Security</strong></div>
            <div className="topbar-status"><span className="status-dot" /> Security console</div>
          </div>
          <div className="route-content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/scan-history" element={<ScanHistory />} />
              <Route path="/resources" element={<Resources />} />
              <Route path="/audit-logs" element={<AuditLogs />} />
              <Route path="/remediation" element={<Remediation />} />
            </Routes>
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
