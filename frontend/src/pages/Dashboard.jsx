
import { useEffect, useState } from "react";
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  Cloud,
  Database,
  Users,
  Server,
  Zap,
  FileSearch,
  RefreshCw,
  Clock3,
  ArrowUpRight,
  CheckCircle2,
  CircleAlert,
  Workflow,
} from "lucide-react";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

const services = [
  { name: "Amazon S3", type: "Storage", icon: Database },
  { name: "AWS IAM", type: "Identity & Access", icon: Users },
  { name: "Amazon EC2", type: "Compute", icon: Server },
  { name: "AWS Lambda", type: "Serverless", icon: Zap },
  { name: "CloudTrail", type: "Audit & Monitoring", icon: FileSearch },
];

function Dashboard() {
  const [dashboard, setDashboard] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastScan, setLastScan] = useState(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [dashboardResponse, findingsResponse] = await Promise.all([
        fetch("http://127.0.0.1:8000/platform/dashboard/"),
        fetch("http://127.0.0.1:8000/platform/findings/"),
      ]);

      if (!dashboardResponse.ok || !findingsResponse.ok) {
        throw new Error("Unable to load dashboard data");
      }

      const dashboardData = await dashboardResponse.json();
      const findingsData = await findingsResponse.json();

      setDashboard(dashboardData);
      setFindings(Array.isArray(findingsData) ? findingsData : []);
    } catch (error) {
      console.error("Error fetching dashboard data:", error);
    } finally {
      setLoading(false);
    }
  };

  const runSecurityScan = async () => {
    try {
      setLoading(true);

      const response = await fetch(
        "http://127.0.0.1:8000/platform/scans/run",
        { method: "POST" }
      );

      if (!response.ok) throw new Error("Scan failed");

      await response.json();
      setLastScan(new Date());
      await fetchDashboardData();

      alert("Security scan completed successfully!");
    } catch (error) {
      console.error("Error running scan:", error);
      alert("Failed to run security scan");
    } finally {
      setLoading(false);
    }
  };

  const severityData = [
    { name: "Critical", count: dashboard?.critical ?? 0 },
    { name: "High", count: dashboard?.high ?? 0 },
    { name: "Medium", count: dashboard?.medium ?? 0 },
    { name: "Low", count: dashboard?.low ?? 0 },
  ];

  const score = dashboard?.security_score;
  const scoreLabel =
    score == null ? "Awaiting data" :
    score >= 80 ? "Healthy posture" :
    score >= 60 ? "Needs attention" : "High risk";

  const workflowCounts = [
    {
      label: "Open findings",
      count: findings.filter(
        (item) => !["resolved", "closed", "fixed"].includes(
          String(item.status || "").toLowerCase()
        )
      ).length,
      className: "workflow-open",
    },
    {
      label: "In progress",
      count: findings.filter(
        (item) => String(item.status || "").toLowerCase().includes("progress")
      ).length,
      className: "workflow-progress",
    },
    {
      label: "Resolved",
      count: findings.filter(
        (item) => ["resolved", "closed", "fixed"].includes(
          String(item.status || "").toLowerCase()
        )
      ).length,
      className: "workflow-resolved",
    },
  ];

  if (loading && !dashboard) {
    return <div className="loading">Loading CloudSentinel...</div>;
  }

  return (
    <div className="soc-dashboard">
      <header className="soc-header">
        <div>
          <div className="eyebrow">
            <span className="live-dot" />
            CLOUD SECURITY OPERATIONS
          </div>
          <h1>Cloud Security Overview</h1>
          <p>Monitor your AWS environment, findings, and remediation activity.</p>
        </div>

        <button
          className="scan-btn"
          onClick={runSecurityScan}
          disabled={loading}
        >
          <RefreshCw size={16} className={loading ? "spin-icon" : ""} />
          {loading ? "Scanning..." : "Run Security Scan"}
        </button>
      </header>

      <section className="soc-kpi-grid">
        <article className="soc-kpi score-kpi">
          <div className="kpi-top">
            <span>Security posture</span>
            <ShieldCheck size={19} />
          </div>
          <div className="score-line">
            <strong>{score ?? "--"}</strong>
            <span>/ 100</span>
          </div>
          <div className="score-track">
            <span style={{ width: `${Math.min(100, Math.max(0, Number(score) || 0))}%` }} />
          </div>
          <small>{scoreLabel}</small>
        </article>

        <article className="soc-kpi">
          <div className="kpi-top">
            <span>Total findings</span>
            <ShieldAlert size={19} />
          </div>
          <strong>{dashboard?.total_findings ?? "--"}</strong>
          <small>Security issues detected</small>
        </article>

        <article className="soc-kpi">
          <div className="kpi-top">
            <span>Scans completed</span>
            <Activity size={19} />
          </div>
          <strong>{dashboard?.total_scans ?? "--"}</strong>
          <small>Recorded assessments</small>
        </article>

        <article className="soc-kpi">
          <div className="kpi-top">
            <span>Resources scanned</span>
            <Cloud size={19} />
          </div>
          <strong>{dashboard?.resources_scanned ?? "--"}</strong>
          <small>AWS resources monitored</small>
        </article>
      </section>

      <section className="soc-panel service-panel">
        <div className="soc-section-heading">
          <div>
            <h2>AWS service health</h2>
            <p>Services covered by CloudSentinel security scans</p>
          </div>
          <span className="section-tag">AWS ENVIRONMENT</span>
        </div>

        <div className="service-grid">
          {services.map((service) => {
            const Icon = service.icon;
            return (
              <article className="service-card" key={service.name}>
                <div className="service-icon"><Icon size={20} /></div>
                <div className="service-copy">
                  <strong>{service.name}</strong>
                  <span>{service.type}</span>
                </div>
                <span className="service-indicator" title="Service health not connected" />
                <small className="service-status">Scan target</small>
              </article>
            );
          })}
        </div>
        <p className="panel-note">
          Service cards show scan coverage, not live AWS availability.
        </p>
      </section>

      <section className="soc-main-grid">
        <article className="soc-panel chart-panel">
          <div className="soc-section-heading">
            <div>
              <h2>Finding severity</h2>
              <p>Current findings grouped by severity</p>
            </div>
            <div className="panel-icon"><Activity size={18} /></div>
          </div>

          <div className="severity-summary">
            {severityData.map((item) => (
              <div className="severity-mini" key={item.name}>
                <span className={`severity-dot ${item.name.toLowerCase()}`} />
                <span>{item.name}</span>
                <strong>{item.count}</strong>
              </div>
            ))}
          </div>

          <div className="soc-chart">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={severityData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="#273247" strokeDasharray="4 4" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: "#98a6bd", fontSize: 12 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: "#98a6bd", fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    background: "#111827",
                    border: "1px solid #334155",
                    borderRadius: 10,
                    color: "#f1f5f9",
                  }}
                />
                <Bar dataKey="count" name="Findings" fill="#8b5cf6" radius={[5, 5, 0, 0]} maxBarSize={42} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </article>

        <article className="soc-panel workflow-panel">
          <div className="soc-section-heading">
            <div>
              <h2>Remediation workflow</h2>
              <p>Finding status from your current records</p>
            </div>
            <Workflow size={19} className="heading-icon" />
          </div>

          <div className="workflow-list">
            {workflowCounts.map((item) => (
              <div className="workflow-row" key={item.label}>
                <div className={`workflow-symbol ${item.className}`}>
                  {item.className === "workflow-resolved"
                    ? <CheckCircle2 size={18} />
                    : item.className === "workflow-progress"
                    ? <Clock3 size={18} />
                    : <CircleAlert size={18} />}
                </div>
                <span>{item.label}</span>
                <strong>{item.count}</strong>
              </div>
            ))}
          </div>

          <div className="workflow-footer">
            <span>Findings tracked</span>
            <strong>{findings.length}</strong>
          </div>
          <p className="panel-note">
            Status counts are based on findings returned by the API.
          </p>
        </article>
      </section>

      <section className="soc-main-grid bottom-grid">
        <article className="soc-panel activity-panel">
          <div className="soc-section-heading">
            <div>
              <h2>Scan activity</h2>
              <p>Activity recorded during this session</p>
            </div>
            <Clock3 size={19} className="heading-icon" />
          </div>

          <div className="activity-timeline">
            <div className="timeline-entry">
              <span className="timeline-marker"><CheckCircle2 size={15} /></span>
              <div>
                <strong>Dashboard opened</strong>
                <p>CloudSentinel monitoring view loaded</p>
                <small>Current session</small>
              </div>
              <span className="timeline-pill">Active</span>
            </div>

            {lastScan && (
              <div className="timeline-entry">
                <span className="timeline-marker"><RefreshCw size={15} /></span>
                <div>
                  <strong>Security scan completed</strong>
                  <p>A scan was started from this dashboard</p>
                  <small>{lastScan.toLocaleTimeString()}</small>
                </div>
                <span className="timeline-pill completed">Completed</span>
              </div>
            )}

            {!lastScan && (
              <div className="timeline-empty">
                <Clock3 size={17} />
                <span>Run a scan to record activity in this session.</span>
              </div>
            )}
          </div>
        </article>

        <article className="soc-panel priority-panel">
          <div className="soc-section-heading">
            <div>
              <h2>Recent findings</h2>
              <p>Latest issues returned by your backend</p>
            </div>
            <ArrowUpRight size={19} className="heading-icon" />
          </div>

          <div className="priority-list">
            {findings.length > 0 ? findings.slice(0, 5).map((finding) => (
              <div className="priority-row" key={finding.id}>
                <span className={`priority-severity ${(finding.severity || "info").toLowerCase()}`} />
                <div className="priority-copy">
                  <strong>{finding.title || "Untitled finding"}</strong>
                  <span>{finding.description || "No description provided."}</span>
                </div>
                <span className={`badge ${(finding.severity || "info").toLowerCase()}-badge`}>
                  {finding.severity || "Info"}
                </span>
              </div>
            )) : (
              <div className="priority-empty">
                <ShieldCheck size={24} />
                <strong>No findings returned</strong>
                <span>Findings will appear here when available.</span>
              </div>
            )}
          </div>
        </article>
      </section>
    </div>
  );
}

export default Dashboard;
