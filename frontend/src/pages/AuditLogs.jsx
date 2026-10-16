import { useEffect, useState } from "react";

function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/platform/audit-logs/")
      .then((response) => response.json())
      .then((data) => {
        setLogs(data);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching audit logs:", error);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <h2>Loading audit logs...</h2>;
  }

  const parseDetails = (rawDetails) => {
    if (!rawDetails) return { text: "-", actor: null, source: null };
    try {
      const parsed = JSON.parse(rawDetails);
      if (typeof parsed === "object" && parsed !== null) {
        return {
          text: parsed.user_details || parsed.details || JSON.stringify(parsed),
          actor: parsed.actor || parsed.recorded_by || null,
          source: parsed.source || null,
        };
      }
    } catch {
      // Plain text or legacy format
    }
    return { text: rawDetails, actor: null, source: null };
  };

  return (
    <div className="page">
      <h1>Audit Logs</h1>
      <p className="page-subtitle">
        Track security activities and actions performed in CloudSentinel.
      </p>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Action</th>
              <th>Resource Type</th>
              <th>Resource ID</th>
              <th>Details & Operator</th>
              <th>Time</th>
            </tr>
          </thead>

          <tbody>
            {logs.length === 0 ? (
              <tr>
                <td colSpan="5">No audit logs found.</td>
              </tr>
            ) : (
              logs.map((log) => {
                const parsed = parseDetails(log.details);
                return (
                  <tr key={log.id}>
                    <td>
                      <strong>{log.action}</strong>
                    </td>
                    <td>{log.resource_type || "-"}</td>
                    <td>{log.resource_id || "-"}</td>
                    <td>
                      <div>{parsed.text}</div>
                      {parsed.actor && (
                        <div style={{ marginTop: "4px" }}>
                          <span className="badge badge-status-executed" style={{ fontSize: "10px", padding: "2px 6px" }}>
                            👤 {parsed.actor}
                          </span>
                          {parsed.source && (
                            <span style={{ fontSize: "11px", color: "#9ca3af", marginLeft: "6px" }}>
                              via {parsed.source}
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                    <td>
                      {log.created_at
                        ? new Date(log.created_at).toLocaleString()
                        : "-"}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AuditLogs;