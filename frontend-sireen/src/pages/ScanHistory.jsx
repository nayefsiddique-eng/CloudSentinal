import { useEffect, useState } from "react";

function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const response = await fetch(
        "http://127.0.0.1:8000/platform/scans/"
      );

      const data = await response.json();
      setScans(data);
    } catch (error) {
      console.error("Error fetching scan history:", error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="loading">Loading scan history...</div>;
  }

  return (
    <>
      <header className="header">
        <div>
          <h1>Scan History</h1>
          <p>View previously completed AWS security assessments.</p>
        </div>
      </header>

      <section className="findings-section">
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Scan Type</th>
                <th>Status</th>
                <th>Total Findings</th>
                <th>High</th>
                <th>Medium</th>
                <th>Low</th>
                <th>Created At</th>
              </tr>
            </thead>

            <tbody>
              {scans.length > 0 ? (
                scans.map((scan) => (
                  <tr key={scan.id}>
                    <td>#{scan.id}</td>
                    <td>{scan.scan_type}</td>
                    <td>{scan.status}</td>
                    <td>{scan.total_findings}</td>
                    <td>{scan.high_findings}</td>
                    <td>{scan.medium_findings}</td>
                    <td>{scan.low_findings}</td>
                    <td>
                      {scan.created_at
                        ? new Date(scan.created_at).toLocaleString()
                        : "N/A"}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="8">No scan history available.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

export default ScanHistory;