import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";

function Remediation() {
  const { session, setSession, login, logout, checkSession } = useAuth();
  const [remediations, setRemediations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errorBanner, setErrorBanner] = useState(null);
  const [successBanner, setSuccessBanner] = useState(null);
  const [actionInProgress, setActionInProgress] = useState(null);

  const [showLoginModal, setShowLoginModal] = useState(false);
  const [loginForm, setLoginForm] = useState({ username: "", password: "" });
  const [loginInProgress, setLoginInProgress] = useState(false);

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    setLoginInProgress(true);
    setErrorBanner(null);
    try {
      const data = await login(loginForm.username, loginForm.password);
      setSuccessBanner(`Signed in as ${data.username} (${data.role}). Session established via HttpOnly cookie.`);
      await fetchRemediations();
    } catch (err) {
      setErrorBanner(err.message);
    } finally {
      setLoginInProgress(false);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
      setSuccessBanner("Successfully logged out. Session destroyed.");
    } catch (err) {
      console.error("Logout error:", err);
    }
  };

  const fetchRemediations = async () => {
    try {
      const response = await fetch("http://127.0.0.1:8000/platform/remediation/", {
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error(`Server returned ${response.status}: ${response.statusText}`);
      }
      const data = await response.json();
      setRemediations(data);
    } catch (error) {
      console.error("Error fetching remediation tasks:", error);
      setErrorBanner("Failed to load remediation records. Please ensure backend is running.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkSession();
    fetchRemediations();
  }, [checkSession]);

  const handleAction = async (id, action) => {
    setErrorBanner(null);
    setSuccessBanner(null);
    setActionInProgress(id);

    try {
      // Build headers without ANY shared API keys
      const headers = {
        "Content-Type": "application/json",
      };

      // Add CSRF token from session cookie for Double-Submit CSRF protection
      if (session.csrf_token) {
        headers["X-CSRF-Token"] = session.csrf_token;
      }

      const response = await fetch(
        `http://127.0.0.1:8000/platform/remediation/${id}/${action}`,
        {
          method: "PUT",
          headers: headers,
          credentials: "include", // Transmit HttpOnly session cookie
        }
      );

      const result = await response.json();

      if (!response.ok) {
        if (response.status === 401) {
          setSession({ authenticated: false, username: null, csrf_token: null });
          throw new Error("Session expired or unauthenticated. Please sign in to approve actions.");
        }
        if (response.status === 403) {
          throw new Error(result.detail || "Forbidden: CSRF validation failed or insufficient permissions.");
        }
        throw new Error(result.detail || `Action '${action}' failed with status ${response.status}`);
      }

      setSuccessBanner(
        action === "approve"
          ? `Remediation #${id} approved & executed successfully by ${result.approved_by || session.username}.`
          : `Remediation #${id} rejected by ${session.username || "operator"}.`
      );

      await fetchRemediations();
    } catch (error) {
      console.error(`Error performing ${action}:`, error);
      setErrorBanner(error.message);
      await fetchRemediations();
    } finally {
      setActionInProgress(null);
    }
  };

  const getTierBadgeClass = (tier) => {
    switch (tier) {
      case "AUTO_ALLOWED":
        return "badge-tier-auto";
      case "APPROVAL_REQUIRED":
        return "badge-tier-approval";
      case "NEVER_AUTO":
      default:
        return "badge-tier-never";
    }
  };

  const getStatusBadgeClass = (status) => {
    switch (status) {
      case "EXECUTED":
        return "badge-status-executed";
      case "REJECTED":
        return "badge-status-rejected";
      case "BLOCKED":
      case "FAILED":
        return "badge-status-failed";
      case "LEGACY_SCAN_REQUIRED":
        return "badge-status-legacy";
      case "PENDING":
      default:
        return "badge-status-pending";
    }
  };

  if (loading) {
    return <div className="loading" style={{ padding: "40px", textAlign: "center" }}>Loading remediation tasks...</div>;
  }

  return (
    <>
      <header className="header">
        <div>
          <h1>Remediation Center</h1>
          <p>
            Safety-Gated Autonomous and Human-Approved Cloud Remediation Workflows
          </p>
        </div>
        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          {session.authenticated ? (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "0.85rem", color: "#38bdf8" }}>
                👤 {session.username} ({session.role})
              </span>
              <button
                className="scan-btn"
                style={{ background: "#334155", color: "#e2e8f0" }}
                onClick={handleLogout}
              >
                Sign Out
              </button>
            </div>
          ) : (
            <button
              className="scan-btn"
              style={{ background: "#0284c7" }}
              onClick={() => setShowLoginModal(true)}
            >
              Sign In to Remediate
            </button>
          )}

          <button
            className="scan-btn"
            onClick={() => {
              setLoading(true);
              fetchRemediations();
            }}
          >
            Refresh Tasks
          </button>
        </div>
      </header>

      {/* Interactive Login Modal */}
      {showLoginModal && !session.authenticated && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: "rgba(0,0,0,0.7)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 9999
        }}>
          <div style={{
            background: "#1e293b",
            padding: "24px",
            borderRadius: "8px",
            border: "1px solid #334155",
            width: "360px",
            color: "#f8fafc"
          }}>
            <h3 style={{ margin: "0 0 12px 0", fontSize: "1.1rem" }}>Remediation Operator Sign In</h3>
            <p style={{ fontSize: "0.85rem", color: "#94a3b8", marginBottom: "16px" }}>
              Authenticate with your server-side security operator credentials to approve cloud remediations.
            </p>
            <form onSubmit={async (e) => {
              await handleLogin(e);
              setShowLoginModal(false);
            }}>
              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "0.8rem", color: "#cbd5e1", marginBottom: "4px" }}>Username</label>
                <input
                  type="text"
                  required
                  value={loginForm.username}
                  onChange={(e) => setLoginForm({ ...loginForm, username: e.target.value })}
                  placeholder="admin"
                  style={{
                    width: "100%",
                    padding: "8px 10px",
                    background: "#0f172a",
                    border: "1px solid #475569",
                    borderRadius: "4px",
                    color: "white"
                  }}
                />
              </div>
              <div style={{ marginBottom: "16px" }}>
                <label style={{ display: "block", fontSize: "0.8rem", color: "#cbd5e1", marginBottom: "4px" }}>Password</label>
                <input
                  type="password"
                  required
                  value={loginForm.password}
                  onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                  placeholder="••••••••••••"
                  style={{
                    width: "100%",
                    padding: "8px 10px",
                    background: "#0f172a",
                    border: "1px solid #475569",
                    borderRadius: "4px",
                    color: "white"
                  }}
                />
              </div>
              <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end" }}>
                <button
                  type="button"
                  onClick={() => setShowLoginModal(false)}
                  style={{
                    background: "#475569",
                    color: "white",
                    border: "none",
                    padding: "8px 14px",
                    borderRadius: "4px",
                    cursor: "pointer"
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loginInProgress}
                  style={{
                    background: "#0284c7",
                    color: "white",
                    border: "none",
                    padding: "8px 16px",
                    borderRadius: "4px",
                    cursor: "pointer"
                  }}
                >
                  {loginInProgress ? "Signing in..." : "Sign In"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Security notice documenting Cookie & CSRF architecture */}
      <div style={{
        backgroundColor: "#0f172a",
        color: "#94a3b8",
        padding: "12px 16px",
        borderRadius: "8px",
        marginBottom: "16px",
        fontSize: "0.85rem",
        border: "1px solid #1e293b",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between"
      }}>
        <span>
          <strong style={{ color: "#38bdf8" }}>Zero Browser Secrets:</strong> Authentication is handled via secure <code style={{ color: "#f1f5f9" }}>HttpOnly</code> session cookies with Double-Submit CSRF protection. No server API keys or passwords exist in frontend code or network transmissions.
        </span>
        <span style={{
          fontSize: "0.75rem",
          background: session.authenticated ? "#14532d" : "#7f1d1d",
          color: session.authenticated ? "#86efac" : "#fca5a5",
          padding: "3px 10px",
          borderRadius: "4px",
          fontWeight: "bold"
        }}>
          {session.authenticated ? "SESSION ACTIVE" : "UNAUTHENTICATED"}
        </span>
      </div>

      {errorBanner && (
        <div style={{
          backgroundColor: "#7f1d1d",
          color: "#fecaca",
          padding: "12px 16px",
          borderRadius: "8px",
          marginBottom: "20px",
          border: "1px solid #b91c1c"
        }}>
          <strong>Notice: </strong> {errorBanner}
        </div>
      )}

      {successBanner && (
        <div style={{
          backgroundColor: "#14532d",
          color: "#bbf7d0",
          padding: "12px 16px",
          borderRadius: "8px",
          marginBottom: "20px",
          border: "1px solid #16a34a"
        }}>
          <strong>Success: </strong> {successBanner}
        </div>
      )}

      <section className="dashboard-section">
        <div className="table-container">
          <table className="findings-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Target Resource</th>
                <th>Safety Policy & Tier</th>
                <th>Status</th>
                <th>Recommended Action</th>
                <th>Approval Action</th>
              </tr>
            </thead>
            <tbody>
              {remediations.length > 0 ? (
                remediations.map((item) => (
                  <tr key={item.id}>
                    <td>#{item.id}</td>
                    <td>
                      <strong>{item.resource_id || "Global"}</strong>
                      <div style={{ fontSize: "11px", color: "#9ca3af" }}>
                        {item.resource_type || "AWS Resource"}
                      </div>
                    </td>
                    <td>
                      <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                        <div>
                          <span className={`badge ${getTierBadgeClass(item.safety_tier)}`}>
                            {item.safety_tier}
                          </span>
                          {" "}
                          <span className={`badge ${item.implementation_status === "IMPLEMENTED" ? "badge-status-executed" : "badge-status-failed"}`}>
                            {item.implementation_status}
                          </span>
                        </div>
                        <div style={{ fontSize: "11px", color: "#6b7280" }}>
                          {item.reason}
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className={`badge ${getStatusBadgeClass(item.status)}`}>
                        {item.status}
                      </span>
                    </td>
                    <td>
                      <div style={{ maxWidth: "340px" }}>
                        <div style={{ fontWeight: 600 }}>{item.title}</div>
                        <div style={{ fontSize: "12px", color: "#9ca3af", marginTop: "2px" }}>
                          {item.recommendation}
                        </div>
                        {item.manual_instructions && (
                          <details style={{ marginTop: "6px", fontSize: "11px", color: "#60a5fa" }}>
                            <summary style={{ cursor: "pointer" }}>View Manual Remediation Guide</summary>
                            <pre style={{
                              whiteSpace: "pre-wrap",
                              background: "#111827",
                              padding: "8px",
                              borderRadius: "4px",
                              marginTop: "4px",
                              color: "#e5e7eb"
                            }}>
                              {item.manual_instructions}
                            </pre>
                          </details>
                        )}
                      </div>
                    </td>
                    <td>
                      {item.status === "PENDING" ? (
                        item.can_execute ? (
                          <div style={{ display: "flex", gap: "8px" }}>
                            <button
                              disabled={actionInProgress === item.id}
                              style={{
                                background: "#059669",
                                color: "white",
                                border: "none",
                                padding: "6px 12px",
                                borderRadius: "4px",
                                cursor: "pointer",
                                opacity: actionInProgress === item.id ? 0.6 : 1
                              }}
                              onClick={() => handleAction(item.id, "approve")}
                            >
                              {actionInProgress === item.id ? "Running..." : "Approve & Apply"}
                            </button>

                            <button
                              disabled={actionInProgress === item.id}
                              style={{
                                background: "#475569",
                                color: "white",
                                border: "none",
                                padding: "6px 12px",
                                borderRadius: "4px",
                                cursor: "pointer"
                              }}
                              onClick={() => handleAction(item.id, "reject")}
                            >
                              Reject
                            </button>
                          </div>
                        ) : (
                          <div style={{ fontSize: "12px", color: "#f87171" }}>
                            {item.safety_tier === "NEVER_AUTO"
                              ? "⚠️ Manual Console Fix Only"
                              : "⚠️ Automated Fix Unavailable"}
                          </div>
                        )
                      ) : (
                        <span style={{ fontSize: "12px", color: "#9ca3af" }}>
                          {item.status === "EXECUTED" ? "Completed" : item.status}
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" style={{ textAlign: "center", padding: "24px" }}>
                    No remediation tasks available. Run a security scan to populate findings.
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