import { useEffect, useState } from "react";

function Resources() {
  const [resources, setResources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("http://127.0.0.1:8000/platform/resources/")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Failed to fetch resources");
        }
        return response.json();
      })
      .then((data) => {
        setResources(data);
        setLoading(false);
      })
      .catch((error) => {
        console.error(error);
        setError("Could not load resources");
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <h2>Loading resources...</h2>;
  }

  if (error) {
    return <h2>{error}</h2>;
  }

  return (
    <div className="resources-page">
      <h1>Cloud Resources</h1>
      <p>Discovered AWS resources from security scans</p>

      <div className="resource-summary">
        <div className="summary-card">
          <h3>Total Resources</h3>
          <p>{resources.length}</p>
        </div>

        <div className="summary-card">
          <h3>S3 Buckets</h3>
          <p>
            {
              resources.filter(
                (resource) => resource.resource_type === "s3_bucket"
              ).length
            }
          </p>
        </div>
      </div>

      <div className="resources-table-container">
        <table className="resources-table">
          <thead>
            <tr>
              <th>Resource ID</th>
              <th>Type</th>
              <th>Name</th>
              <th>Region</th>
              <th>Created</th>
            </tr>
          </thead>

          <tbody>
            {resources.map((resource) => (
              <tr key={resource.id}>
                <td>{resource.resource_id}</td>
                <td>{resource.resource_type}</td>
                <td>{resource.resource_name || "-"}</td>
                <td>{resource.region || "-"}</td>
                <td>
                  {resource.created_at
                    ? new Date(resource.created_at).toLocaleString()
                    : "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {resources.length === 0 && (
          <p className="no-resources">
            No resources found. Run a scan first.
          </p>
        )}
      </div>
    </div>
  );
}

export default Resources;