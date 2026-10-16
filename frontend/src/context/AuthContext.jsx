import { createContext, useContext, useEffect, useState, useCallback } from "react";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [session, setSession] = useState({
    authenticated: false,
    username: null,
    role: null,
    csrf_token: null,
  });
  const [loading, setLoading] = useState(true);

  const checkSession = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/auth/me", {
        credentials: "include",
      });
      if (res.ok) {
        const data = await res.json();
        setSession(data);
      } else {
        setSession({ authenticated: false, username: null, role: null, csrf_token: null });
      }
    } catch (err) {
      console.warn("Could not check session status:", err);
      setSession({ authenticated: false, username: null, role: null, csrf_token: null });
    } finally {
      setLoading(false);
    }
  }, []);

  const login = async (username, password) => {
    const res = await fetch("http://127.0.0.1:8000/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "Authentication failed");
    }
    const updated = {
      authenticated: true,
      username: data.username,
      role: data.role,
      csrf_token: data.csrf_token,
    };
    setSession(updated);
    return updated;
  };

  const logout = async () => {
    try {
      await fetch("http://127.0.0.1:8000/auth/logout", {
        method: "POST",
        credentials: "include",
      });
    } catch (err) {
      console.error("Logout error:", err);
    } finally {
      setSession({ authenticated: false, username: null, role: null, csrf_token: null });
    }
  };

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  return (
    <AuthContext.Provider value={{ session, setSession, loading, checkSession, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
