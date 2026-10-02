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
              <th>Details</th>
              <th>Time</th>
            </tr>
          </thead>

          <tbody>
            {logs.length === 0 ? (
              <tr>
                <td colSpan="5">No audit logs found.</td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id}>
                  <td>{log.action}</td>
                  <td>{log.resource_type || "-"}</td>
                  <td>{log.resource_id || "-"}</td>
                  <td>{log.details || "-"}</td>
                  <td>
                    {log.created_at
                      ? new Date(log.created_at).toLocaleString()
                      : "-"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AuditLogs;