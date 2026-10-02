import { useEffect, useState } from "react";

function Findings() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    fetchFindings();
  }, []);

  const fetchFindings = async () => {
    try {
      const response = await fetch(
        "http://127.0.0.1:8000/platform/findings/"
      );

      const data = await response.json();
      setFindings(data);
    } catch (error) {
      console.error("Error fetching findings:", error);
    } finally {
      setLoading(false);
    }
  };

  const filteredFindings = findings.filter((finding) => {
    const searchableText = [
      finding.title,
      finding.description,
      finding.explanation,
      finding.impact,
      finding.attack_scenario,
      finding.recommendation,
      finding.priority,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    const matchesSearch = searchableText.includes(search.toLowerCase());

    const matchesSeverity =
      severityFilter === "ALL" ||
      finding.severity?.toUpperCase() === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  const toggleExpanded = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const getSeverityLabel = (severity) => {
    if (!severity) return "Unknown";

    return (
      severity.charAt(0).toUpperCase() +
      severity.slice(1).toLowerCase()
    );
  };

  const getHumanTitle = (finding) => {
    if (
      finding.title &&
      finding.title !== "Unknown Finding"
    ) {
      return finding.title;
    }

    const text = `${finding.explanation || ""} ${
      finding.description || ""
    }`.toLowerCase();

    if (
      text.includes("overly permissive") ||
      text.includes("wildcard") ||
      text.includes("excessive permissions")
    ) {
      return "Excessive AWS Permissions";
    }

    if (
      text.includes("mfa") ||
      text.includes("multi-factor")
    ) {
      return "Multi-Factor Authentication Not Enabled";
    }

    if (
      text.includes("encryption") ||
      text.includes("data protection")
    ) {
      return "Cloud Data Protection Needs Attention";
    }

    if (text.includes("public access")) {
      return "Public Access Configuration";
    }

    return "Security Finding";
  };

  if (loading) {
    return <div className="loading">Loading security insights...</div>;
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Security Findings</h1>
          <p>
            CloudSentinel analyzes your AWS environment and explains
            security risks in simple language.
          </p>
        </div>
      </div>

      {/* Search and Filter */}
      <div className="findings-controls">
        <input
          type="text"
          placeholder="Search security findings..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="search-input"
        />

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="severity-select"
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>
      </div>

      <div className="results-count">
        Showing {filteredFindings.length} of {findings.length} findings
      </div>

      {/* AI Finding Cards */}
      <div className="ai-findings-list">
        {filteredFindings.length > 0 ? (
          filteredFindings.map((finding) => {
            const isExpanded = expandedId === finding.id;

            return (
              <div
                className="ai-finding-card"
                key={finding.id}
              >
                {/* Header */}
                <div className="ai-finding-header">
                  <div>
                    <span
                      className={`badge ${finding.severity?.toLowerCase()}-badge`}
                    >
                      {getSeverityLabel(finding.severity)}
                    </span>

                    {finding.priority && (
                      <span className="priority-badge">
                        {finding.priority}
                      </span>
                    )}
                  </div>

                  <span className="finding-status">
                    {finding.status || "OPEN"}
                  </span>
                </div>

                {/* Finding title */}
                <h2 className="ai-finding-title">
                  {getHumanTitle(finding)}
                </h2>

                {/* AI Explanation */}
                <div className="ai-section">
                  <div className="ai-section-title">
                    <span>💡</span>
                    <strong>What's happening?</strong>
                  </div>

                  <p>
                    {finding.explanation ||
                      finding.description ||
                      "CloudSentinel detected a security issue that requires attention."}
                  </p>
                </div>

                {/* Impact */}
                {finding.impact && (
                  <div className="ai-section">
                    <div className="ai-section-title">
                      <span>⚠️</span>
                      <strong>Why does this matter?</strong>
                    </div>

                    <p>{finding.impact}</p>
                  </div>
                )}

                {/* Recommendation */}
                {finding.recommendation && (
                  <div className="ai-section recommendation-section">
                    <div className="ai-section-title">
                      <span>🛠️</span>
                      <strong>What should you do?</strong>
                    </div>

                    <p>{finding.recommendation}</p>
                  </div>
                )}

                {/* Risk information */}
                <div className="finding-meta">
                  {finding.risk_level && (
                    <div className="meta-item">
                      <span>Risk</span>
                      <strong>{finding.risk_level}</strong>
                    </div>
                  )}

                  {finding.risk_score !== null &&
                    finding.risk_score !== undefined && (
                      <div className="meta-item">
                        <span>Risk Score</span>
                        <strong>{finding.risk_score}</strong>
                      </div>
                    )}

                  {finding.confidence && (
                    <div className="meta-item">
                      <span>AI Confidence</span>
                      <strong>{finding.confidence}</strong>
                    </div>
                  )}
                </div>

                {/* Technical Details */}
                <button
                  className="technical-toggle"
                  onClick={() => toggleExpanded(finding.id)}
                >
                  <span>
                    {isExpanded ? "▾" : "▸"} Technical details
                  </span>

                  <span>
                    {isExpanded ? "Hide" : "View"}
                  </span>
                </button>

                {isExpanded && (
                  <div className="technical-details">
                    <div className="technical-row">
                      <span>Finding ID</span>
                      <strong>{finding.id || "—"}</strong>
                    </div>

                    <div className="technical-row">
                      <span>Title</span>
                      <strong>{finding.title || "—"}</strong>
                    </div>

                    <div className="technical-row">
                      <span>Resource</span>
                      <strong>
                        {finding.resource_id || "Not available"}
                      </strong>
                    </div>

                    <div className="technical-row">
                      <span>Attack Scenario</span>
                      <strong>
                        {finding.attack_scenario || "Not available"}
                      </strong>
                    </div>

                    <div className="technical-row">
                      <span>Priority</span>
                      <strong>
                        {finding.priority || "Not assigned"}
                      </strong>
                    </div>

                    {finding.description && (
                      <div className="technical-description">
                        <span>Technical Description</span>
                        <p>{finding.description}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        ) : (
          <div className="empty-state">
            <h3>No findings found</h3>
            <p>
              No security findings match your current search or
              severity filter.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Findings;