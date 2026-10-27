import { useState } from "react";
import {
  api,
  AuthorizedNetwork,
  NetworkRoute,
} from "../lib/api";
import { useToast } from "../components/Toast";
import ActionButton from "../components/ActionButton";

interface SettingsWorkspaceProps {
  networks: AuthorizedNetwork[];
  routes: NetworkRoute[];
  safeMode: boolean;
  setSafeMode: (val: boolean) => void;
  onRefresh: () => Promise<void>;
}

export default function SettingsWorkspace({
  networks,
  routes,
  safeMode,
  setSafeMode,
  onRefresh,
}: SettingsWorkspaceProps) {
  const { toast } = useToast();

  // Network form state
  const [newCidr, setNewCidr] = useState("");
  const [newCidrDesc, setNewCidrDesc] = useState("");
  const [selectedRouteId, setSelectedRouteId] = useState<string>("");
  const [isAddingNetwork, setIsAddingNetwork] = useState(false);

  // Route form state
  const [newRouteName, setNewRouteName] = useState("");
  const [pivotHost, setPivotHost] = useState("");
  const [pivotPort, setPivotPort] = useState("22");
  const [pivotUser, setPivotUser] = useState("");
  const [pivotSecret, setPivotSecret] = useState("");
  const [isAddingRoute, setIsAddingRoute] = useState(false);

  // Route test state
  const [routeTestingId, setRouteTestingId] = useState<number | null>(null);
  const [routeTestResult, setRouteTestResult] = useState<Record<number, string>>({});

  // Intelligence Settings (Perplexity)
  const [perplexityKey, setPerplexityKey] = useState(() => localStorage.getItem("pret_pplx_api_key") || "");
  const [pplxModel, setPplxModel] = useState(() => localStorage.getItem("pret_pplx_model") || "sonar");
  const [pplxTestStatus, setPplxTestStatus] = useState<string | null>(null);
  const [isTestingPplx, setIsTestingPplx] = useState(false);

  async function handleAddNetwork(e: React.FormEvent) {
    e.preventDefault();
    if (!newCidr.trim()) return;
    setIsAddingNetwork(true);
    try {
      const rId = selectedRouteId ? parseInt(selectedRouteId, 10) : null;
      await api.addAuthorizedNetwork(newCidr.trim(), newCidrDesc.trim(), rId);
      setNewCidr("");
      setNewCidrDesc("");
      setSelectedRouteId("");
      toast.success(`Authorized network ${newCidr} added to scope.`, "Network Added");
      await onRefresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to add network", "Scope Error");
    } finally {
      setIsAddingNetwork(false);
    }
  }

  async function handleDeleteNetwork(id: number) {
    try {
      await api.deleteAuthorizedNetwork(id);
      toast.success("Authorized CIDR subnet removed from scope.", "Scope Updated");
      await onRefresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete network", "Scope Error");
    }
  }

  async function handleAddRoute(e: React.FormEvent) {
    e.preventDefault();
    if (!newRouteName.trim() || !pivotHost.trim() || !pivotUser.trim() || !pivotSecret.trim()) return;
    setIsAddingRoute(true);
    try {
      await api.addRoute({
        name: newRouteName.trim(),
        pivot_host: pivotHost.trim(),
        pivot_port: parseInt(pivotPort, 10) || 22,
        pivot_username: pivotUser.trim(),
        credential: pivotSecret,
      });
      setNewRouteName("");
      setPivotHost("");
      setPivotUser("");
      setPivotSecret("");
      toast.success("SSH Pivot Route added successfully.", "Route Configured");
      await onRefresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to add route", "Route Error");
    } finally {
      setIsAddingRoute(false);
    }
  }

  async function handleDeleteRoute(id: number) {
    try {
      await api.deleteRoute(id);
      toast.success("SSH Pivot Route removed.", "Route Removed");
      await onRefresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete route", "Route Error");
    }
  }

  async function handleTestRoute(id: number) {
    setRouteTestingId(id);
    setRouteTestResult((prev) => ({ ...prev, [id]: "Testing connection..." }));
    try {
      const res = await api.testRoute(id);
      setRouteTestResult((prev) => ({ ...prev, [id]: res.message }));
      toast.info(res.message, "SSH Connection Test");
    } catch (err) {
      const msg = `Connection failed: ${err instanceof Error ? err.message : "Error"}`;
      setRouteTestResult((prev) => ({ ...prev, [id]: msg }));
      toast.error(msg, "SSH Test Failed");
    } finally {
      setRouteTestingId(null);
    }
  }

  function handleSaveIntelligenceSettings() {
    localStorage.setItem("pret_pplx_api_key", perplexityKey.trim());
    localStorage.setItem("pret_pplx_model", pplxModel);
    toast.success("Intelligence provider settings saved locally.", "Settings Saved");
  }

  async function handleTestPerplexity() {
    if (!perplexityKey.trim()) {
      toast.warning("Please provide a Perplexity API key to test.", "Missing Key");
      return;
    }
    setIsTestingPplx(true);
    setPplxTestStatus("Contacting Perplexity API...");
    try {
      const res = await fetch("https://api.perplexity.ai/chat/completions", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${perplexityKey.trim()}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: pplxModel,
          messages: [
            { role: "system", content: "You are a test ping for security reporting." },
            { role: "user", content: "Reply with the word OK." },
          ],
          max_tokens: 10,
        }),
      });

      if (res.ok) {
        setPplxTestStatus("✅ Perplexity API connection verified successfully!");
        toast.success("Perplexity API key and model verified.", "API Online");
      } else {
        const errJson = await res.json().catch(() => ({}));
        const errMsg = errJson.error?.message || `HTTP ${res.status} ${res.statusText}`;
        setPplxTestStatus(`❌ API Error: ${errMsg}`);
        toast.error(`Perplexity error: ${errMsg}`, "Connection Failed");
      }
    } catch (err) {
      const msg = `Connection error: ${err instanceof Error ? err.message : "Failed"}`;
      setPplxTestStatus(`❌ ${msg}`);
      toast.error(msg, "Network Error");
    } finally {
      setIsTestingPplx(false);
    }
  }

  return (
    <div className="settings-workspace">
      {/* SCOPE ENFORCEMENT PANEL */}
      <div className="panel" style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12, marginBottom: 12 }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 18 }}>Authorized Network Scope (LAN Boundary Enforcement)</h2>
            <p className="sub" style={{ margin: "4px 0 0" }}>
              The PRET engine strictly enforces network scope barriers. Any connection request to an IP not in these subnets is categorically rejected.
            </p>
          </div>
          <span className="pill" style={{ background: "rgba(52, 211, 153, 0.15)", color: "#34d399", fontWeight: 700 }}>
            🛡️ Server-Side Scope Active
          </span>
        </div>

        <form onSubmit={handleAddNetwork} className="row" style={{ alignItems: "flex-end", gap: 10 }}>
          <div style={{ flex: 2 }}>
            <label>CIDR Network Subnet</label>
            <input
              value={newCidr}
              onChange={(e) => setNewCidr(e.target.value)}
              placeholder="e.g. 172.16.128.0/18 or 192.168.1.0/24"
              required
            />
          </div>
          <div style={{ flex: 2 }}>
            <label>Description / Location</label>
            <input
              value={newCidrDesc}
              onChange={(e) => setNewCidrDesc(e.target.value)}
              placeholder="e.g. Campus Lab Subnet"
            />
          </div>
          <div style={{ flex: 2 }}>
            <label>Routing (Direct or Pivot)</label>
            <select
              value={selectedRouteId}
              onChange={(e) => setSelectedRouteId(e.target.value)}
              style={{ height: 38 }}
            >
              <option value="">Direct Network Connection (No Pivot)</option>
              {routes.map((r) => (
                <option key={r.id} value={r.id}>
                  SSH Pivot: {r.name} ({r.pivot_host})
                </option>
              ))}
            </select>
          </div>
          <div>
            <ActionButton
              type="submit"
              variant="blue"
              isLoading={isAddingNetwork}
              loadingText="Authorizing..."
              style={{ height: 38, marginBottom: 1, whiteSpace: "nowrap" }}
            >
              + Authorize Subnet
            </ActionButton>
          </div>
        </form>

        <table style={{ marginTop: 16 }}>
          <thead>
            <tr>
              <th>Authorized CIDR Subnet</th>
              <th>Description</th>
              <th>Routing Mode</th>
              <th style={{ textAlign: "right" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {networks.map((net) => {
              const assignedRoute = routes.find((r) => r.id === net.route_id);
              return (
                <tr key={net.id}>
                  <td>
                    <strong><code>{net.cidr}</code></strong>
                  </td>
                  <td>{net.description || "—"}</td>
                  <td>
                    {assignedRoute ? (
                      <span className="pill source">SSH Pivot: {assignedRoute.name}</span>
                    ) : (
                      <span className="pill">Direct LAN</span>
                    )}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <button
                      type="button"
                      className="btn-red btn-sm"
                      onClick={() => handleDeleteNetwork(net.id)}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {networks.length === 0 && (
          <p className="empty">No authorized subnets configured. All target additions will be refused by default.</p>
        )}
      </div>

      {/* SSH PIVOT ROUTES PANEL */}
      <div className="panel" style={{ marginBottom: 18 }}>
        <h2 style={{ margin: "0 0 6px", fontSize: 18 }}>SSH Pivot & Jump Host Routes</h2>
        <p className="sub" style={{ margin: "0 0 16px" }}>
          Configure dual-homed SSH bastion hosts to reach isolated printer VLANs without altering backend security logic.
        </p>

        <form onSubmit={handleAddRoute}>
          <div className="row">
            <div>
              <label>Route Identifier Name</label>
              <input
                value={newRouteName}
                onChange={(e) => setNewRouteName(e.target.value)}
                placeholder="e.g. Pivot-VLAN-10"
                required
              />
            </div>
            <div>
              <label>SSH Pivot Host</label>
              <input
                value={pivotHost}
                onChange={(e) => setPivotHost(e.target.value)}
                placeholder="192.168.10.1"
                required
              />
            </div>
            <div>
              <label>SSH Port</label>
              <input
                value={pivotPort}
                onChange={(e) => setPivotPort(e.target.value)}
                placeholder="22"
              />
            </div>
          </div>
          <div className="row" style={{ marginTop: 10 }}>
            <div>
              <label>SSH Username</label>
              <input
                value={pivotUser}
                onChange={(e) => setPivotUser(e.target.value)}
                placeholder="admin"
                required
              />
            </div>
            <div>
              <label>Password or Private Key (Encrypted at Rest)</label>
              <input
                type="password"
                value={pivotSecret}
                onChange={(e) => setPivotSecret(e.target.value)}
                placeholder="Password or SSH Private Key"
                required
              />
            </div>
          </div>
          <ActionButton
            type="submit"
            variant="teal"
            isLoading={isAddingRoute}
            loadingText="Adding Route..."
            style={{ marginTop: 12 }}
          >
            + Add SSH Pivot Route
          </ActionButton>
        </form>

        <table style={{ marginTop: 16 }}>
          <thead>
            <tr>
              <th>Route Name</th>
              <th>Pivot Endpoint</th>
              <th>Username</th>
              <th>Connectivity Test</th>
              <th style={{ textAlign: "right" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {routes.map((r) => (
              <tr key={r.id}>
                <td>
                  <strong>{r.name}</strong>
                </td>
                <td>
                  <code>{r.pivot_host}:{r.pivot_port}</code>
                </td>
                <td>{r.pivot_username}</td>
                <td>
                  <ActionButton
                    variant="ghost"
                    size="sm"
                    isLoading={routeTestingId === r.id}
                    loadingText="Connecting..."
                    onClick={() => handleTestRoute(r.id)}
                  >
                    Test Connection
                  </ActionButton>
                  {routeTestResult[r.id] && (
                    <div
                      style={{
                        fontSize: 11,
                        marginTop: 4,
                        color: routeTestResult[r.id].includes("Success") ? "#34d399" : "#f87171",
                      }}
                    >
                      {routeTestResult[r.id]}
                    </div>
                  )}
                </td>
                <td style={{ textAlign: "right" }}>
                  <button
                    type="button"
                    className="btn-red btn-sm"
                    onClick={() => handleDeleteRoute(r.id)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {routes.length === 0 && <p className="empty">No SSH pivot routes configured.</p>}
      </div>

      {/* INTELLIGENCE & REMEDIATION PROVIDER (PERPLEXITY AGENT API) */}
      <div className="panel" style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, marginBottom: 12 }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 18 }}>Intelligence & AI Remediation Engine (Perplexity Agent)</h2>
            <p className="sub" style={{ margin: "4px 0 0" }}>
              Post-assessment read-only intelligence provider. Synthesizes findings, CVE references, and step-by-step remediation runbooks.
            </p>
          </div>
          <span className="pill" style={{ background: "rgba(56, 189, 248, 0.15)", color: "#38bdf8", fontWeight: 700 }}>
            Strict Read-Only Post-Assessment
          </span>
        </div>

        <div className="row">
          <div style={{ flex: 3 }}>
            <label>Perplexity API Key</label>
            <input
              type="password"
              value={perplexityKey}
              onChange={(e) => setPerplexityKey(e.target.value)}
              placeholder="pplx-xxxxxxxxxxxxxxxxxxxxxxxx"
            />
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              Stored securely in browser storage. Target IPs and credentials are redacted locally before query.
            </span>
          </div>

          <div style={{ flex: 2 }}>
            <label>AI Model</label>
            <select
              value={pplxModel}
              onChange={(e) => setPplxModel(e.target.value)}
              style={{ height: 38 }}
            >
              <option value="sonar">sonar (Fast & Concise)</option>
              <option value="sonar-pro">sonar-pro (In-depth CVE Analysis & Reasoning)</option>
            </select>
          </div>
        </div>

        <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 14, flexWrap: "wrap" }}>
          <button type="button" className="btn-blue" onClick={handleSaveIntelligenceSettings}>
            💾 Save Intelligence Settings
          </button>
          <ActionButton
            variant="ghost"
            isLoading={isTestingPplx}
            loadingText="Verifying..."
            onClick={handleTestPerplexity}
          >
            ⚡ Test Perplexity Connection
          </ActionButton>
        </div>

        {pplxTestStatus && (
          <p
            style={{
              marginTop: 10,
              fontSize: 13,
              color: pplxTestStatus.startsWith("✅") ? "#34d399" : "#f87171",
            }}
          >
            {pplxTestStatus}
          </p>
        )}
      </div>

      {/* PLATFORM TELEMETRY & SAFE MODE CONTROLLER */}
      <div className="panel">
        <h2 style={{ margin: "0 0 6px", fontSize: 18 }}>System Telemetry & Engine Guards</h2>
        <p className="sub" style={{ margin: "0 0 16px" }}>
          Current engine execution environment, safe mode locks, and process runtime info.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 14 }}>
          <div style={{ padding: 12, background: "var(--panel2)", borderRadius: 6, border: "1px solid var(--border)" }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
              Safe Mode Lock
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
              <input
                type="checkbox"
                checked={safeMode}
                onChange={(e) => setSafeMode(e.target.checked)}
                style={{ width: 18, height: 18 }}
              />
              <span style={{ fontWeight: 700, color: safeMode ? "#34d399" : "#f87171" }}>
                {safeMode ? "ACTIVE (Destructive Locked)" : "DISENGAGED (Confirm Required)"}
              </span>
            </div>
          </div>

          <div style={{ padding: 12, background: "var(--panel2)", borderRadius: 6, border: "1px solid var(--border)" }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
              PRET Engine Binary
            </div>
            <div style={{ fontSize: 13, fontWeight: 600, marginTop: 6 }}>
              <code>d:\AcademicPlanning\PRET\pret\pret.py</code>
            </div>
          </div>

          <div style={{ padding: 12, background: "var(--panel2)", borderRadius: 6, border: "1px solid var(--border)" }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
              Runtime Architecture
            </div>
            <div style={{ fontSize: 13, fontWeight: 600, marginTop: 6 }}>
              Python 3.12 (Windows) • Pure-Python Concurrency
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
