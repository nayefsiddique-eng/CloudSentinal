import { useEffect, useState } from "react";

function Remediation() {
  const [remediations, setRemediations] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchRemediations = async () => {
    try {
      const response = await fetch(
        "http://127.0.0.1:8000/platform/remediation/"
      );

      const data = await response.json();
      setRemediations(data);
    } catch (error) {
      console.error("Error fetching remediation tasks:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRemediations();
  }, []);

  const updateStatus = async (id, action) => {
    try {
      await fetch(
        `http://127.0.0.1:8000/platform/remediation/${id}/${action}`,
        {
          method: "PUT",
        }
      );

      fetchRemediations();
    } catch (error) {
      console.error("Error updating remediation:", error);
    }
  };

  if (loading) {
    return <div className="loading">Loading remediation tasks...</div>;
  }

  return (
    <>
      <header className="header">
        <div>
          <h1>Remediation Center</h1>
          <p>
            Review and approve recommended actions to improve cloud security.
          </p>
        </div>
      </header>

      <section className="findings-section">
        <div className="section-header">
          <h2>Recommended Security Actions</h2>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Description</th>
                <th>Recommendation</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody>
              {remediations.length > 0 ? (
                remediations.map((item) => (
                  <tr key={item.id}>
                    <td>{item.title}</td>

                    <td>{item.description}</td>

                    <td>{item.recommendation}</td>

                    <td>
                      <span className="badge">
                        {item.status}
                      </span>
                    </td>

                    <td>
                      {item.status === "PENDING" ? (
                        <>
                          <button
                            onClick={() =>
                              updateStatus(item.id, "approve")
                            }
                          >
                            Approve
                          </button>

                          <button
                            onClick={() =>
                              updateStatus(item.id, "reject")
                            }
                          >
                            Reject
                          </button>
                        </>
                      ) : (
                        <span>{item.status}</span>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5">
                    No remediation tasks available.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

export default Remediation;