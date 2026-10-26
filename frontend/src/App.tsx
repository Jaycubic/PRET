import { useState } from "react";
import { getToken, clearToken } from "./lib/api";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";

export default function App() {
  const [loggedIn, setLoggedIn] = useState(!!getToken());

  function logout() {
    clearToken();
    setLoggedIn(false);
  }

  if (!loggedIn) {
    return <Login onLoggedIn={() => setLoggedIn(true)} />;
  }

  return (
    <div>
      <header>
        <div className="brand">
          🖨️ PRET Web UI <small>Printer Exploitation Toolkit — Authorized LAN Use Only</small>
        </div>
        <div className="badge">🛡️ LAN Mode (Server-Enforced Scope)</div>
        <div className="hdr-right">
          <button className="btn-ghost" onClick={logout}>Log out</button>
        </div>
      </header>
      <Dashboard />
    </div>
  );
}
