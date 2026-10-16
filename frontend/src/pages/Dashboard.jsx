import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

function Dashboard() {
  const { session } = useAuth();
  const [dashboard, setDashboard] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanMessage, setScanMessage] = useState(null);
  const [scanError, setScanError] = useState(null);

  const fetchDashboardData = async () => {
    try {
      const dashboardResponse = await fetch(
        "http://127.0.0.1:8000/platform/dashboard/",
        { credentials: "include" }
      );
      const dashboardData = await dashboardResponse.json();

      const findingsResponse = await fetch(
        "http://127.0.0.1:8000/platform/findings/",
        { credentials: "include" }
      );
      const findingsData = await findingsResponse.json();

      setDashboard(dashboardData);
      setFindings(findingsData);
    } catch (error) {
      console.error("Error fetching dashboard data:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const runSecurityScan = async () => {
    setScanMessage(null);
    setScanError(null);

    if (!session.authenticated) {
      setScanError("Authentication required: Please sign in from the Remediation Center to run security scans.");
      return;
    }

    try {
      setLoading(true);

      const headers = { "Content-Type": "application/json" };
      if (session.csrf_token) {
        headers["X-CSRF-Token"] = session.csrf_token;
      }

      const response = await fetch(
        "http://127.0.0.1:8000/platform/scans/run",
        {
          method: "POST",
          headers: headers,
          credentials: "include",
        }
      );

      const resData = await response.json();

      if (!response.ok) {
        throw new Error(resData.detail || "Scan request failed");
      }

      await fetchDashboardData();
      setScanMessage(`Scan #${resData.scan_id || ""} completed successfully! Detected ${resData.total_findings || 0} findings.`);
    } catch (error) {
      console.error("Error running scan:", error);
      setScanError(error.message || "Failed to run security scan");
    } finally {
      setLoading(false);
    }
  };

  if (loading && !dashboard) {
    return <div className="loading">Loading CloudSentinel Dashboard...</div>;
  }

  const severityData = [
  {
    name: "Critical",
    count: dashboard?.critical ?? 0,
  },
  {
    name: "High",
    count: dashboard?.high ?? 0,
  },
  {
    name: "Medium",
    count: dashboard?.medium ?? 0,
  },
  {
    name: "Low",
    count: dashboard?.low ?? 0,
  },
];

  return (
    <>
      <header className="header">
        <div>
          <h1>Security Dashboard</h1>
          <p>Monitor and analyze your AWS cloud security posture.</p>
        </div>

        <button
          className="scan-btn"
          onClick={runSecurityScan}
          disabled={loading}
        >
          {loading ? "Scanning..." : "Run Security Scan"}
        </button>
      </header>

      {scanError && (
        <div style={{
          background: "#7f1d1d",
          border: "1px solid #ef4444",
          color: "#fecaca",
          padding: "12px 16px",
          borderRadius: "8px",
          marginBottom: "24px",
          fontSize: "14px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center"
        }}>
          <div><strong>Error: </strong> {scanError}</div>
          <button
            onClick={() => setScanError(null)}
            style={{ background: "transparent", border: "none", color: "#fecaca", cursor: "pointer", fontWeight: "bold" }}
          >
            ✕
          </button>
        </div>
      )}

      {scanMessage && (
        <div style={{
          background: "#064e3b",
          border: "1px solid #10b981",
          color: "#d1fae5",
          padding: "12px 16px",
          borderRadius: "8px",
          marginBottom: "24px",
          fontSize: "14px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center"
        }}>
          <div><strong>Success: </strong> {scanMessage}</div>
          <button
            onClick={() => setScanMessage(null)}
            style={{ background: "transparent", border: "none", color: "#d1fae5", cursor: "pointer", fontWeight: "bold" }}
          >
            ✕
          </button>
        </div>
      )}

      <section className="stats-grid">
        <div className="stat-card score-card">
  <p>Security Score</p>

  <div className="score-display">
    <div className="score-circle">
      <h2>{dashboard?.security_score ?? "--"}</h2>
      <span>/100</span>
    </div>
  </div>

  <div className="risk-level">
    {dashboard?.security_score >= 80
      ? "LOW RISK"
      : dashboard?.security_score >= 60
      ? "MEDIUM RISK"
      : "HIGH RISK"}
  </div>

  <span>Overall cloud security posture</span>
</div>
        <div className="stat-card">
          <p>Total Findings</p>
          <h2>{dashboard?.total_findings ?? "--"}</h2>
          <span>Detected vulnerabilities</span>
        </div>

        <div className="stat-card">
          <p>Total Scans</p>
          <h2>{dashboard?.total_scans ?? "--"}</h2>
          <span>Security assessments completed</span>
        </div>

        <div className="stat-card">
          <p>Resources Scanned</p>
          <h2>{dashboard?.resources_scanned ?? "--"}</h2>
          <span>AWS resources monitored</span>
        </div>
      </section>

      <section className="severity-section">
        <h2>Findings by Severity</h2>

        <div className="severity-grid">
          <div className="severity-card critical">
            <span>Critical</span>
            <h2>{dashboard?.critical ?? 0}</h2>
          </div>

          <div className="severity-card high">
            <span>High</span>
            <h2>{dashboard?.high ?? 0}</h2>
          </div>

          <div className="severity-card medium">
            <span>Medium</span>
            <h2>{dashboard?.medium ?? 0}</h2>
          </div>

          <div className="severity-card low">
            <span>Low</span>
            <h2>{dashboard?.low ?? 0}</h2>
          </div>
        </div>
      </section>

      <section className="chart-section">
  <div className="chart-card">
    <h2>Security Findings Overview</h2>
    <p>Distribution of findings across severity levels.</p>

    <div className="chart-container">
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={severityData}>
          <XAxis dataKey="name" />
          <YAxis allowDecimals={false} />
          <Tooltip />
          <Bar dataKey="count" radius={[6, 6, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  </div>
</section>

      <section className="findings-section">
        <div className="section-header">
          <h2>Recent Findings</h2>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding</th>
                <th>Description</th>
                <th>Status</th>
              </tr>
            </thead>

            <tbody>
              {findings.length > 0 ? (
                findings.slice(0, 5).map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <span
                        className={`badge ${finding.severity?.toLowerCase()}-badge`}
                      >
                        {finding.severity}
                      </span>
                    </td>
                    <td>{finding.title}</td>
                    <td>{finding.description}</td>
                    <td>{finding.status}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="4">No findings available.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

export default Dashboard;