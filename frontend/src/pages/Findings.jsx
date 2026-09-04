import { useEffect, useState } from "react";

function Findings() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");

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
    const matchesSearch =
      finding.title?.toLowerCase().includes(search.toLowerCase()) ||
      finding.description?.toLowerCase().includes(search.toLowerCase());

    const matchesSeverity =
      severityFilter === "ALL" ||
      finding.severity?.toUpperCase() === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  if (loading) {
    return <div className="loading">Loading findings...</div>;
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Security Findings</h1>
          <p>
            Review and monitor security vulnerabilities detected across your
            cloud infrastructure.
          </p>
        </div>
      </div>

      {/* Search and Filter */}
      <div className="findings-controls">
        <input
          type="text"
          placeholder="Search findings..."
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

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Finding</th>
              <th>Description</th>
              <th>Recommendation</th>
              <th>Status</th>
            </tr>
          </thead>

          <tbody>
            {filteredFindings.length > 0 ? (
              filteredFindings.map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <span
                      className={`badge ${finding.severity?.toLowerCase()}-badge`}
                    >
                      {finding.severity}
                    </span>
                  </td>

                  <td>{finding.title}</td>

                  <td>{finding.description || "-"}</td>

                  <td>{finding.recommendation || "-"}</td>

                  <td>{finding.status}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="5">No findings match your filters.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default Findings;