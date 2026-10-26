import { useEffect, useState, useRef } from "react";
import {
  api,
  Device,
  AdapterInfo,
  Operation,
  AuditEntry,
  AuthorizedNetwork,
  NetworkRoute,
  JobResult,
  CupsQueue,
  CveFinding,
  ExploitVerifyResult,
  ProbeResult,
} from "../lib/api";
import ConfirmModal from "../components/ConfirmModal";
import JobLog from "../components/JobLog";

type NavTab = "dashboard" | "discovered" | "logs" | "settings";

export default function Dashboard() {
  const [currentTab, setCurrentTab] = useState<NavTab>("dashboard");
  const [devices, setDevices] = useState<Device[]>([]);
  const [adapters, setAdapters] = useState<AdapterInfo[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [networks, setNetworks] = useState<AuthorizedNetwork[]>([]);
  const [routes, setRoutes] = useState<NetworkRoute[]>([]);
  const [selected, setSelected] = useState<Device | null>(null);

  // Forms & state
  const [ip, setIp] = useState("");
  const [port, setPort] = useState("9100");
  const [targetKind, setTargetKind] = useState<"printer" | "cups_server">("printer");
  const [deviceFilter, setDeviceFilter] = useState<"all" | "printer" | "print_server">("all");
  const [deviceResults, setDeviceResults] = useState<JobResult[]>([]);
  const [investigatingCups, setInvestigatingCups] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [pendingConfirm, setPendingConfirm] = useState<Operation | null>(null);
  const [activeJobId, setActiveJobId] = useState<number | null>(null);
  const [safeMode, setSafeMode] = useState(true);

  // Port Probe / Scan state
  const [probing, setProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);
  const [detectedModel, setDetectedModel] = useState<string>("");

  // Discovery feedback
  const [discovering, setDiscovering] = useState(false);
  const [discStatus, setDiscStatus] = useState<string | null>(null);

  // Settings forms
  const [newCidr, setNewCidr] = useState("");
  const [newCidrDesc, setNewCidrDesc] = useState("");
  const [selectedRouteId, setSelectedRouteId] = useState<string>("");
  const [settingsMsg, setSettingsMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const [newRouteName, setNewRouteName] = useState("");
  const [pivotHost, setPivotHost] = useState("");
  const [pivotPort, setPivotPort] = useState("22");
  const [pivotUser, setPivotUser] = useState("");
  const [pivotSecret, setPivotSecret] = useState("");
  const [routeTestingId, setRouteTestingId] = useState<number | null>(null);
  const [routeTestResult, setRouteTestResult] = useState<Record<number, string>>({});

  // Exploitation verification state
  const [exploitLogs, setExploitLogs] = useState<string[]>([]);
  const [exploitRunning, setExploitRunning] = useState(false);
  const [exploitResult, setExploitResult] = useState<ExploitVerifyResult | null>(null);
  const [exploitError, setExploitError] = useState<string | null>(null);
  const exploitTerminalRef = useRef<HTMLDivElement>(null);
  const exploitAbortRef = useRef<AbortController | null>(null);

  // Audit filter
  const [auditSearch, setAuditSearch] = useState("");

  async function refresh() {
    try {
      const [d, a, l] = await Promise.all([
        api.listDevices(),
        api.listAdapters(),
        api.auditLog(),
      ]);
      setDevices(d);
      setAdapters(a);
      setAudit(l);

      if (currentTab === "settings") {
        const [nets, rts] = await Promise.all([
          api.listNetworks().catch(() => []),
          api.listRoutes().catch(() => []),
        ]);
        setNetworks(nets);
        setRoutes(rts);
      }
    } catch {
      // Ignore background refresh errors
    }
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 6000);
    return () => clearInterval(t);
  }, [currentTab]);

  useEffect(() => {
    if (selected) {
      api.getDeviceResults(selected.id)
        .then(setDeviceResults)
        .catch(() => setDeviceResults([]));
    } else {
      setDeviceResults([]);
    }
  }, [selected]);

  async function handleProbeTarget() {
    if (!ip.trim()) return;
    setProbeError(null);
    setProbing(true);
    try {
      const res = await api.probeTarget(ip.trim());
      setProbeResult(res);
      if (res.recommended_port) {
        setPort(res.recommended_port.toString());
      }
      if (res.device_type) {
        setTargetKind(res.device_type === "print_server" ? "cups_server" : "printer");
      }
      if (res.detected_model) {
        setDetectedModel(res.detected_model);
      }
    } catch (err) {
      setProbeError(err instanceof Error ? err.message : "Port probe failed");
    } finally {
      setProbing(false);
    }
  }

  async function handleProbeDevice(dev: Device) {
    try {
      const res = await api.probeDevice(dev.id);
      setSelected(res.device);
      refresh();
      alert(`Port Scan for ${dev.ip_or_hostname}:\n${res.probe.summary}\nOpen Ports: ${res.probe.open_ports.join(", ")}`);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Device probe failed");
    }
  }

  async function addDevice() {
    if (!ip.trim()) return;
    setAddError(null);
    const parsedPort = parseInt(port, 10) || (targetKind === "cups_server" ? 631 : 9100);
    const devType = targetKind === "cups_server" ? "print_server" : "printer";
    try {
      const dev = await api.addDevice(ip.trim(), parsedPort, devType, detectedModel || undefined);
      setIp("");
      setProbeResult(null);
      setDetectedModel("");
      await refresh();
      setSelected(dev);
    } catch (err) {
      setAddError(err instanceof Error ? err.message : "Failed to add device");
    }
  }

  async function handleInvestigateCups() {
    if (!ip.trim()) return;
    setAddError(null);
    setInvestigatingCups(true);
    const parsedPort = parseInt(port, 10) || 631;
    try {
      const resp = await api.investigateCups(ip.trim(), parsedPort);
      setIp("");
      await refresh();
      setSelected(resp.device);
      api.getDeviceResults(resp.device.id).then(setDeviceResults).catch(() => {});
    } catch (err) {
      setAddError(err instanceof Error ? err.message : "CUPS investigation failed");
    } finally {
      setInvestigatingCups(false);
    }
  }

  async function runOperation(device: Device, op: Operation, confirmed: boolean) {
    const adapterId = adapters.find((a) => a.operations.some((o) => o.id === op.id))?.id;
    if (!adapterId) return;
    if (!op.read_only && safeMode) {
      alert("Blocked: Safe Mode is ON. Turn it off to run state-changing operations.");
      return;
    }
    try {
      const job = await api.createJob(device.id, adapterId, op.id, confirmed);
      setActiveJobId(job.id);
      setTimeout(refresh, 1200);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to start job");
    }
  }

  function onOperationClick(device: Device, op: Operation) {
    if (op.read_only) {
      runOperation(device, op, false);
    } else {
      setSelected(device);
      setPendingConfirm(op);
    }
  }

  async function triggerDiscovery(type: "mdns" | "wsd") {
    setDiscovering(true);
    setDiscStatus(`Scanning local network via ${type.toUpperCase()}...`);
    try {
      const res = type === "mdns" ? await api.runMdnsDiscovery() : await api.runWsdDiscovery();
      const count = (res.found_services ?? res.found_devices) || 0;
      setDiscStatus(
        `Discovered ${count} device(s). Added ${res.added_devices.length} in-scope; skipped ${res.skipped_out_of_scope.length} out-of-scope.`
      );
      await refresh();
    } catch (err) {
      setDiscStatus(`Discovery error: ${err instanceof Error ? err.message : "Failed"}`);
    } finally {
      setDiscovering(false);
    }
  }

  async function handleAddNetwork(e: React.FormEvent) {
    e.preventDefault();
    if (!newCidr.trim()) return;
    setSettingsMsg(null);
    try {
      const rId = selectedRouteId ? parseInt(selectedRouteId, 10) : null;
      await api.addAuthorizedNetwork(newCidr.trim(), newCidrDesc.trim(), rId);
      setNewCidr("");
      setNewCidrDesc("");
      setSelectedRouteId("");
      setSettingsMsg({ type: "ok", text: `Authorized network ${newCidr} added successfully.` });
      const nets = await api.listNetworks();
      setNetworks(nets);
    } catch (err) {
      setSettingsMsg({ type: "err", text: err instanceof Error ? err.message : "Failed to add network" });
    }
  }

  async function handleDeleteNetwork(id: number) {
    if (!confirm("Are you sure you want to remove this authorized network?")) return;
    try {
      await api.deleteAuthorizedNetwork(id);
      const nets = await api.listNetworks();
      setNetworks(nets);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete network");
    }
  }

  async function handleAddRoute(e: React.FormEvent) {
    e.preventDefault();
    if (!newRouteName.trim() || !pivotHost.trim() || !pivotUser.trim() || !pivotSecret.trim()) return;
    setSettingsMsg(null);
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
      setSettingsMsg({ type: "ok", text: "SSH Pivot Route added." });
      const rts = await api.listRoutes();
      setRoutes(rts);
    } catch (err) {
      setSettingsMsg({ type: "err", text: err instanceof Error ? err.message : "Failed to add route" });
    }
  }

  async function handleDeleteRoute(id: number) {
    if (!confirm("Are you sure you want to remove this SSH Pivot Route?")) return;
    try {
      await api.deleteRoute(id);
      const rts = await api.listRoutes();
      setRoutes(rts);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete route");
    }
  }

  async function handleTestRoute(id: number) {
    setRouteTestingId(id);
    setRouteTestResult((prev) => ({ ...prev, [id]: "Testing connection..." }));
    try {
      const res = await api.testRoute(id);
      setRouteTestResult((prev) => ({ ...prev, [id]: res.message }));
    } catch (err) {
      setRouteTestResult((prev) => ({ ...prev, [id]: `Test failed: ${err instanceof Error ? err.message : "Error"}` }));
    } finally {
      setRouteTestingId(null);
    }
  }

  const stats = {
    total: devices.length,
    printers: devices.filter((d) => d.device_type !== "print_server" && d.port !== 631).length,
    cupsServers: devices.filter((d) => d.device_type === "print_server" || d.port === 631).length,
    online: devices.filter((d) => d.status !== "offline").length,
    discovered: devices.filter((d) => d.source && d.source !== "manual").length,
  };

  const filteredAudit = audit.filter((entry) => {
    if (!auditSearch.trim()) return true;
    const q = auditSearch.toLowerCase();
    return (
      entry.action.toLowerCase().includes(q) ||
      entry.outcome.toLowerCase().includes(q) ||
      entry.detail.toLowerCase().includes(q)
    );
  });

  return (
    <div className="layout">
      <nav>
        <a
          className={currentTab === "dashboard" ? "active" : ""}
          onClick={() => { setCurrentTab("dashboard"); refresh(); }}
        >
          🏠 Dashboard
        </a>
        <a
          className={currentTab === "discovered" ? "active" : ""}
          onClick={() => { setCurrentTab("discovered"); refresh(); }}
        >
          🖨️ Discovered Printers
        </a>
        <a
          className={currentTab === "logs" ? "active" : ""}
          onClick={() => { setCurrentTab("logs"); refresh(); }}
        >
          📄 Audit Logs
        </a>
        <a
          className={currentTab === "settings" ? "active" : ""}
          onClick={() => { setCurrentTab("settings"); refresh(); }}
        >
          ⚙️ Settings & Scope
        </a>
      </nav>

      <main>
        {/* VIEW 1: DASHBOARD */}
        {currentTab === "dashboard" && (
          <div>
            <div className="panel">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
                <div>
                  <h2>Printer Exploitation Toolkit Web UI</h2>
                  <p className="sub">
                    Authorized, auditable security assessment platform for networked printers.
                  </p>
                </div>
                <label style={{ display: "flex", alignItems: "center", gap: 10, background: "var(--panel2)", padding: "8px 14px", borderRadius: 8, border: "1px solid var(--border)" }}>
                  <input
                    type="checkbox"
                    checked={safeMode}
                    onChange={(e) => setSafeMode(e.target.checked)}
                  />
                  <span style={{ fontSize: 13, fontWeight: 600, color: safeMode ? "#34d399" : "#f87171" }}>
                    {safeMode ? "🛡️ Safe Mode ON (Destructive Actions Blocked)" : "⚠️ Safe Mode OFF (Confirmation Required)"}
                  </span>
                </label>
              </div>
            </div>

            <div className="stats">
              <div className="stat">
                <div className="pill">Configured Targets</div>
                <div className="n">{stats.total}</div>
              </div>
              <div className="stat">
                <div className="pill">🖨️ Hardware Printers</div>
                <div className="n" style={{ color: "#38bdf8" }}>{stats.printers}</div>
              </div>
              <div className="stat">
                <div className="pill">🖥️ CUPS Print Servers</div>
                <div className="n" style={{ color: "#c084fc" }}>{stats.cupsServers}</div>
              </div>
              <div className="stat">
                <div className="pill">Reachable Targets</div>
                <div className="n" style={{ color: "#34d399" }}>{stats.online}</div>
              </div>
              <div className="stat">
                <div className="pill">Active Protocol Adapters</div>
                <div className="n">{adapters.filter((a) => a.available).length} / {adapters.length}</div>
              </div>
            </div>

            <div className="panel">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, marginBottom: 12 }}>
                <div>
                  <h2 style={{ margin: 0 }}>Add / Investigate Network Target</h2>
                  <p className="sub" style={{ margin: "4px 0 0" }}>
                    Target must reside within an administrator-approved authorized CIDR network.
                  </p>
                </div>
                <div className="segmented-control">
                  <button
                    type="button"
                    className={targetKind === "printer" ? "active" : ""}
                    onClick={() => {
                      setTargetKind("printer");
                      setPort("9100");
                    }}
                  >
                    🖨️ Hardware Printer (Port 9100)
                  </button>
                  <button
                    type="button"
                    className={targetKind === "cups_server" ? "active" : ""}
                    onClick={() => {
                      setTargetKind("cups_server");
                      setPort("631");
                    }}
                  >
                    🛡️ CUPS Print Server (Port 631)
                  </button>
                </div>
              </div>

              <div className="row" style={{ alignItems: "flex-end" }}>
                <div style={{ flex: 2 }}>
                  <label>IP Address / Hostname</label>
                  <input
                    value={ip}
                    onChange={(e) => {
                      setIp(e.target.value);
                      if (probeResult) setProbeResult(null);
                    }}
                    placeholder={targetKind === "cups_server" ? "192.168.1.100 (CUPS Host)" : "192.168.1.50"}
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <label>Port ({targetKind === "cups_server" ? "Default 631" : "Default 9100"})</label>
                  <input
                    value={port}
                    onChange={(e) => setPort(e.target.value)}
                    placeholder={targetKind === "cups_server" ? "631" : "9100"}
                  />
                </div>
                <button
                  type="button"
                  className="btn-ghost"
                  disabled={probing || !ip.trim()}
                  onClick={handleProbeTarget}
                  style={{ whiteSpace: "nowrap", height: 38, marginBottom: 1 }}
                >
                  {probing ? "⏳ Probing Ports..." : "🔍 Auto-Scan Ports"}
                </button>
              </div>

              {probeResult && (
                <div className="probe-results-card">
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: "#38bdf8" }}>
                      🔍 Port Scan & Fingerprint Results ({probeResult.ip}):
                    </div>
                    {probeResult.detected_model && (
                      <span className="pill" style={{ background: "rgba(56, 189, 248, 0.2)", color: "#38bdf8", fontWeight: 600 }}>
                        🖨️ {probeResult.detected_model}
                      </span>
                    )}
                  </div>
                  <p style={{ margin: "6px 0 8px", fontSize: 12, color: "var(--text-muted)" }}>
                    {probeResult.summary}
                  </p>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                    Detected Open Ports (Click any port to select it):
                  </div>
                  <div className="probe-port-pills">
                    {probeResult.services.map((svc) => (
                      <button
                        type="button"
                        key={svc.port}
                        className={`probe-port-pill ${port === svc.port.toString() ? "active" : ""} ${svc.is_recommended ? "recommended" : ""}`}
                        onClick={() => {
                          setPort(svc.port.toString());
                          if (svc.port === 631 && probeResult.is_cups_server) {
                            setTargetKind("cups_server");
                          } else {
                            setTargetKind("printer");
                          }
                        }}
                      >
                        <strong>{svc.port}</strong> {svc.protocol}
                        {svc.is_recommended && <span style={{ color: "#34d399", fontSize: 10, fontWeight: 700 }}>★ Best</span>}
                        {svc.banner && (
                          <span style={{ fontSize: 10, color: "var(--text-muted)", maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            ({svc.banner})
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {probeError && <p className="error-text" style={{ marginTop: 10 }}>⚠️ {probeError}</p>}
              <br />
              {targetKind === "cups_server" ? (
                <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                  <button
                    className="btn-blue"
                    disabled={investigatingCups}
                    onClick={handleInvestigateCups}
                  >
                    {investigatingCups ? "⏳ Investigating CUPS Server..." : "🛡️ Investigate CUPS Server (Cyber Audit)"}
                  </button>
                  <button className="btn-ghost" onClick={addDevice}>+ Add Device Only</button>
                  <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                    Audits version, CVE-2024-47176 RCE chain, admin auth bypass, and hosted print queues in one step.
                  </span>
                </div>
              ) : (
                <button className="btn-blue" onClick={addDevice}>+ Add Device</button>
              )}
              {addError && <p className="error-text">⚠️ {addError}</p>}
            </div>

            <div className="panel">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 10 }}>
                <div>
                  <h2 style={{ margin: 0 }}>Registered Network Targets</h2>
                  <p className="sub" style={{ margin: "4px 0 0" }}>Printers and print servers discovered or manually added into scope.</p>
                </div>
                <div className="tab-nav" style={{ margin: 0, border: "none" }}>
                  <button
                    className={`tab-btn ${deviceFilter === "all" ? "active" : ""}`}
                    onClick={() => setDeviceFilter("all")}
                  >
                    All ({devices.length})
                  </button>
                  <button
                    className={`tab-btn ${deviceFilter === "printer" ? "active" : ""}`}
                    onClick={() => setDeviceFilter("printer")}
                  >
                    🖨️ Printers ({stats.printers})
                  </button>
                  <button
                    className={`tab-btn ${deviceFilter === "print_server" ? "active" : ""}`}
                    onClick={() => setDeviceFilter("print_server")}
                  >
                    🖥️ CUPS Servers ({stats.cupsServers})
                  </button>
                </div>
              </div>

              <table>
                <thead>
                  <tr>
                    <th>Target IP / Host</th>
                    <th>Type</th>
                    <th>Resolved IP</th>
                    <th>Model / Info</th>
                    <th>Status</th>
                    <th>Source</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {devices
                    .filter((d) => {
                      if (deviceFilter === "printer") return d.device_type !== "print_server" && d.port !== 631;
                      if (deviceFilter === "print_server") return d.device_type === "print_server" || d.port === 631;
                      return true;
                    })
                    .map((d) => (
                    <tr
                      key={d.id}
                      className={`devrow ${selected?.id === d.id ? "selected" : ""}`}
                      onClick={() => setSelected(d)}
                    >
                      <td><strong>{d.ip_or_hostname}</strong></td>
                      <td>
                        {d.device_type === "print_server" || d.port === 631 ? (
                          <span className="badge-server">🖥️ Print Server</span>
                        ) : (
                          <span className="badge-printer">🖨️ Printer</span>
                        )}
                      </td>
                      <td><code>{d.resolved_ip}:{d.port}</code></td>
                      <td>{d.model || d.hostname || (d.device_type === "print_server" ? "CUPS Server" : "Network Printer")}</td>
                      <td>
                        <span className={`dot ${d.status === "online" ? "online" : d.status === "offline" ? "offline" : "unknown"}`} />
                        {d.status}
                      </td>
                      <td><span className="pill">{d.source || "manual"}</span></td>
                      <td>
                        <button
                          className={selected?.id === d.id ? "btn-blue btn-sm" : "btn-ghost btn-sm"}
                          onClick={(e) => { e.stopPropagation(); setSelected(d); }}
                        >
                          {selected?.id === d.id ? "Inspecting" : "Select"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {devices.length === 0 && (
                <p className="empty">No printer devices registered yet. Add one above or run discovery.</p>
              )}
            </div>

            {selected && (
              <div className="panel">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                  <div>
                    <h2>Device Inspector: {selected.ip_or_hostname}</h2>
                    <p className="sub" style={{ margin: 0 }}>
                      Type: <strong>{selected.device_type === "print_server" ? "CUPS Print Server" : "Network Printer"}</strong> • Resolved: <code>{selected.resolved_ip}:{selected.port}</code> • Model: {selected.model || "Unknown"} • Source: {selected.source || "manual"}
                    </p>
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <button
                      className="btn-ghost btn-sm"
                      onClick={() => handleProbeDevice(selected)}
                    >
                      🔍 Scan Ports
                    </button>
                    <button className="btn-ghost btn-sm" onClick={() => setSelected(null)}>✕ Close</button>
                  </div>
                </div>

                {/* CUPS SERVER CYBER SECURITY AUDIT SECTION */}
                {(() => {
                  if (selected.device_type !== "print_server") return null;
                  const latestCups = deviceResults.find(
                    (r) => r.adapter_id === "cups_server" && r.operation_id === "cups_full_audit"
                  ) || deviceResults.find((r) => r.adapter_id === "cups_server");
                  const ev = (latestCups?.evidence_json || {}) as {
                    cups_version?: string;
                    ipp_version?: string;
                    risk_score?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN";
                    udp_631_exposed?: boolean;
                    admin_audit?: { admin_status_code?: number; admin_auth_enforced?: boolean; conf_leak?: boolean };
                    queues?: CupsQueue[];
                    queue_count?: number;
                    cve_findings?: CveFinding[];
                    sensitive_findings?: string[];
                  };

                  return (
                    <div className="cups-audit-card" style={{ marginBottom: 20 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <h3 style={{ margin: 0, fontSize: 16 }}>🛡️ CUPS Print Server Cyber Security Assessment</h3>
                          {ev?.risk_score && (
                            <span className={`risk-pill risk-${ev.risk_score.toLowerCase()}`}>
                              {ev.risk_score} RISK
                            </span>
                          )}
                        </div>
                        <button
                          className="btn-blue btn-sm"
                          onClick={() => {
                            const fullAuditOp = adapters
                              .find((a) => a.id === "cups_server")
                              ?.operations.find((o) => o.id === "cups_full_audit");
                            if (fullAuditOp) onOperationClick(selected, fullAuditOp);
                          }}
                        >
                          ⚡ Run Full CUPS Cyber Audit
                        </button>
                        <button
                          className="btn-exploit"
                          disabled={exploitRunning}
                          onClick={() => {
                            if (!selected) return;
                            setExploitLogs([]);
                            setExploitResult(null);
                            setExploitError(null);
                            setExploitRunning(true);
                            const controller = api.exploitVerifyCups(
                              selected.resolved_ip || selected.ip_or_hostname,
                              selected.port || 631,
                              {
                                onProgress: (msg) => {
                                  setExploitLogs((prev) => [...prev, msg]);
                                  setTimeout(() => {
                                    exploitTerminalRef.current?.scrollTo({
                                      top: exploitTerminalRef.current.scrollHeight,
                                      behavior: "smooth",
                                    });
                                  }, 50);
                                },
                                onComplete: (result) => {
                                  setExploitResult(result);
                                  setExploitRunning(false);
                                  setTimeout(refresh, 1000);
                                },
                                onError: (err) => {
                                  setExploitError(err);
                                  setExploitRunning(false);
                                },
                              },
                            );
                            exploitAbortRef.current = controller;
                          }}
                        >
                          {exploitRunning ? "⏳ Running Exploit Verification..." : "⚡ Real-Time Exploit Verification"}
                        </button>
                      </div>

                      {latestCups ? (
                        <div>
                          <p style={{ marginTop: 10, fontSize: 13.5, color: "var(--text)" }}>
                            <strong>Cyber Summary:</strong> {latestCups.summary}
                          </p>

                          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginTop: 12 }}>
                            <div style={{ background: "rgba(0,0,0,0.25)", padding: 10, borderRadius: 8 }}>
                              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>CUPS Version</div>
                              <div style={{ fontWeight: 600, fontSize: 13 }}>
                                {ev.cups_version ? `CUPS ${ev.cups_version}` : "Not Fingerprinted"}
                              </div>
                              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                                IPP Protocol: {ev.ipp_version || "2.1"}
                              </div>
                            </div>

                            <div style={{ background: "rgba(0,0,0,0.25)", padding: 10, borderRadius: 8 }}>
                              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>UDP:631 cups-browsed</div>
                              <div style={{ fontWeight: 600, fontSize: 13, color: ev.udp_631_exposed ? "#ef4444" : "#34d399" }}>
                                {ev.udp_631_exposed ? "⚠️ RESPONDING (EXPOSED)" : "🛡️ Inactive / Filtered"}
                              </div>
                              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                                RCE Precondition: {ev.udp_631_exposed ? "MET" : "Closed / Blocked"}
                              </div>
                            </div>

                            <div style={{ background: "rgba(0,0,0,0.25)", padding: 10, borderRadius: 8 }}>
                              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>Admin Interface Auth</div>
                              <div style={{ fontWeight: 600, fontSize: 13, color: ev.admin_audit?.admin_status_code === 200 ? "#ef4444" : "#34d399" }}>
                                {ev.admin_audit?.admin_status_code === 200 ? "🚨 UNPROTECTED (HTTP 200)" : "🛡️ Enforced (HTTP 401/403)"}
                              </div>
                              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                                cupsd.conf: {ev.admin_audit?.conf_leak ? "LEAKED!" : "Protected"}
                              </div>
                            </div>

                            <div style={{ background: "rgba(0,0,0,0.25)", padding: 10, borderRadius: 8 }}>
                              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>Hosted Printer Queues</div>
                              <div style={{ fontWeight: 600, fontSize: 13, color: "#60a5fa" }}>
                                {ev.queue_count ?? ev.queues?.length ?? 0} Discovered
                              </div>
                              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                                IPP 0x4002 / HTML
                              </div>
                            </div>
                          </div>

                          {ev.cve_findings && ev.cve_findings.length > 0 && (
                            <div style={{ marginTop: 14 }}>
                              <h4 style={{ margin: "0 0 8px", fontSize: 13 }}>Known CVE Assessment (2024 cups-browsed RCE Chain):</h4>
                              <div className="cve-grid">
                                {ev.cve_findings.map((cve: CveFinding) => (
                                  <div key={cve.cve_id} className={`cve-item ${cve.severity.toLowerCase()}`}>
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                      <strong>{cve.cve_id}</strong>
                                      <span className={`risk-pill risk-${cve.severity.toLowerCase()}`} style={{ fontSize: 10 }}>
                                        CVSS {cve.cvss_score} {cve.severity}
                                      </span>
                                    </div>
                                    <div style={{ fontSize: 11.5, marginTop: 4, fontWeight: 500 }}>{cve.title}</div>
                                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>{cve.detail}</div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {ev.queues && ev.queues.length > 0 && (
                            <div style={{ marginTop: 16 }}>
                              <h4 style={{ margin: "0 0 8px", fontSize: 13 }}>Hosted Printer Queues:</h4>
                              <table style={{ margin: 0 }}>
                                <thead>
                                  <tr>
                                    <th>Queue Name</th>
                                    <th>State</th>
                                    <th>Make / Model</th>
                                    <th>Backend Device URI</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {ev.queues.map((q: CupsQueue) => (
                                    <tr key={q.name}>
                                      <td><strong>{q.name}</strong></td>
                                      <td><span className="pill">{q.state || "unknown"}</span></td>
                                      <td>{q.make_and_model || "Generic Printer"}</td>
                                      <td>
                                        {q.device_uri ? (
                                          <code>
                                            {q.device_uri.includes("@") ? (
                                              <span style={{ color: "#f87171" }}>⚠️ {q.device_uri} (Credentials Leaked!)</span>
                                            ) : (
                                              q.device_uri
                                            )}
                                          </code>
                                        ) : (
                                          <span style={{ color: "var(--text-muted)" }}>None (Virtual Queue)</span>
                                        )}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}

                          {/* LIVE EXPLOITATION VERIFICATION TERMINAL */}
                          {(exploitLogs.length > 0 || exploitRunning || exploitResult || exploitError) && (
                            <div className="exploit-terminal" style={{ marginTop: 16 }}>
                              <div className="exploit-terminal-header">
                                <div className="dots">
                                  <span className="dot-red" />
                                  <span className="dot-yellow" />
                                  <span className="dot-green" />
                                </div>
                                <span className="title">
                                  PRET Exploit Verification Console — {selected.resolved_ip}:{selected.port || 631}
                                </span>
                                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                                  {exploitRunning && (
                                    <button
                                      className="btn-ghost btn-sm"
                                      style={{ fontSize: 11, padding: "3px 8px" }}
                                      onClick={() => {
                                        exploitAbortRef.current?.abort();
                                        setExploitRunning(false);
                                        setExploitLogs((prev) => [...prev, "[ABORTED] Exploitation verification cancelled by operator"]);
                                      }}
                                    >
                                      ✕ Abort
                                    </button>
                                  )}
                                </div>
                              </div>

                              <div className="exploit-terminal-body" ref={exploitTerminalRef}>
                                {exploitLogs.map((line, i) => {
                                  const isPhase = line.includes("[PHASE");
                                  const isSuccess = line.includes("| ") && (
                                    line.includes("EXPLOITABLE") ||
                                    line.includes("RESPONDED") ||
                                    line.includes("ACCEPTED") ||
                                    line.includes("DETECTED") ||
                                    line.includes("LEAKED") ||
                                    line.includes("UNSANITIZED") ||
                                    line.includes("CONFIRMED") ||
                                    line.includes("RCE_CHAIN_CONFIRMED") ||
                                    line.includes("🚨")
                                  );
                                  const isWarning = line.includes("warning") || line.includes("PARTIAL") || line.includes("VERSION_VULNERABLE");
                                  const isError = line.includes("ABORTED") || line.includes("error");
                                  const isComplete = line.includes("VERIFICATION_COMPLETE") || line.includes("CHAIN_SYNTHESIS");

                                  let statusClass = "status-running";
                                  if (isSuccess) statusClass = "status-success";
                                  else if (isWarning) statusClass = "status-warning";
                                  else if (isError) statusClass = "status-error";
                                  else if (isComplete) statusClass = "status-complete";
                                  else if (line.includes("| ") && (line.includes("info") || line.includes("No ") || line.includes("not"))) statusClass = "status-info";

                                  return (
                                    <div
                                      key={i}
                                      className={`exploit-line ${isPhase ? "phase-header" : ""} ${statusClass}`}
                                    >
                                      <span className="timestamp">[{new Date().toTimeString().slice(0, 8)}]</span>
                                      {line}
                                    </div>
                                  );
                                })}
                                {exploitRunning && <span className="exploit-cursor" />}
                              </div>

                              <div className="exploit-status-bar">
                                <div className="status-label">
                                  <span className={`status-dot ${exploitRunning ? "running" : exploitError ? "error" : "complete"}`} />
                                  <span style={{ color: exploitRunning ? "#4ade80" : exploitError ? "#f87171" : "#60a5fa" }}>
                                    {exploitRunning
                                      ? "EXPLOITATION VERIFICATION IN PROGRESS..."
                                      : exploitError
                                        ? `ERROR: ${exploitError}`
                                        : exploitResult
                                          ? `COMPLETE — ${exploitResult.summary}`
                                          : "READY"}
                                  </span>
                                </div>
                                <span style={{ color: "#475569" }}>
                                  {exploitLogs.length} events
                                </span>
                              </div>

                              {/* CVE Verification Summary Pills */}
                              {exploitResult && exploitResult.evidence && (
                                <div style={{ padding: "10px 16px 14px", borderTop: "1px solid #1e3a5f" }}>
                                  <div style={{ fontSize: 12, fontWeight: 600, color: "#94a3b8", marginBottom: 8 }}>
                                    CVE Exploitability Verification Results:
                                  </div>
                                  <div className="exploit-cve-pills">
                                    {["CVE-2024-47176", "CVE-2024-47076", "CVE-2024-47175", "CVE-2024-47177"].map((cve) => {
                                      const confirmed = exploitResult.evidence.exploitable_cves?.includes(cve);
                                      return (
                                        <span
                                          key={cve}
                                          className={`exploit-cve-pill ${confirmed ? "exploitable" : "safe"}`}
                                        >
                                          {confirmed ? "🔓" : "🔒"} {cve}: {confirmed ? "EXPLOITABLE" : "NOT CONFIRMED"}
                                        </span>
                                      );
                                    })}
                                  </div>
                                  {exploitResult.evidence.chain_exploitable && (
                                    <div style={{
                                      marginTop: 10,
                                      padding: "10px 14px",
                                      background: "rgba(239, 68, 68, 0.15)",
                                      border: "1px solid #ef4444",
                                      borderRadius: 8,
                                      color: "#f87171",
                                      fontSize: 12.5,
                                      fontWeight: 600,
                                    }}>
                                      🚨 FULL RCE CHAIN IS EXPLOITABLE — Unauthenticated Remote Code Execution is achievable on this CUPS server.
                                    </div>
                                  )}
                                  {exploitResult.evidence.overall_risk && (
                                    <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 8 }}>
                                      <span style={{ fontSize: 12, color: "#94a3b8" }}>Overall Risk:</span>
                                      <span className={`risk-pill risk-${exploitResult.evidence.overall_risk.toLowerCase()}`}>
                                        {exploitResult.evidence.overall_risk}
                                      </span>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          )}

                          {latestCups.remediation && (
                            <div style={{ marginTop: 14, background: "rgba(30, 41, 59, 0.5)", border: "1px solid var(--border)", borderRadius: 8, padding: 12 }}>
                              <div style={{ fontSize: 12, fontWeight: 600, color: "#38bdf8", marginBottom: 4 }}>
                                🛡️ Defensive Remediation Guidance:
                              </div>
                              <pre style={{ margin: 0, fontSize: 11, whiteSpace: "pre-wrap", fontFamily: "inherit", color: "var(--text-muted)" }}>
                                {latestCups.remediation}
                              </pre>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div style={{ padding: "14px 0", color: "var(--text-muted)", fontSize: 13 }}>
                          No cyber security audit has been run on this CUPS server yet. Click "⚡ Run Full CUPS Cyber Audit" above to check version, CVE-2024-47176 vulnerability, admin auth bypass, and print queues.
                        </div>
                      )}
                    </div>
                  );
                })()}

                <div className="row">
                  <div style={{ flex: 2 }}>
                    <h3>Available Security Assessment Operations</h3>
                    {adapters.map((a) => (
                      <div key={a.id} style={{ marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                          <span className="pill" style={{ fontWeight: 600 }}>{a.display_name}</span>
                          {!a.available && <span className="pill failure">Unavailable: {a.dependency_detail}</span>}
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 8 }}>
                          {a.operations.map((op) => (
                            <button
                              key={op.id}
                              disabled={!a.available}
                              className={op.read_only ? "quickbtn btn-teal" : "quickbtn btn-red"}
                              onClick={() => onOperationClick(selected, op)}
                            >
                              <div>
                                <div style={{ fontWeight: 600 }}>{op.display_name}</div>
                                <div style={{ fontSize: 11, opacity: 0.85, fontWeight: 400, marginTop: 2 }}>
                                  {op.read_only ? "Read-Only" : "⚠️ State-Changing"} • {op.description}
                                </div>
                              </div>
                            </button>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div style={{ flex: 1 }}>
                    <h3>Device Audit Trail</h3>
                    <div className="log-box">
                      {audit
                        .filter((entry) => !entry.detail || entry.detail.includes(selected.ip_or_hostname) || entry.detail.includes(selected.resolved_ip))
                        .slice(0, 15)
                        .map((entry) => (
                          <div className="logline" key={entry.id}>
                            [{entry.timestamp.slice(11, 19)}] {entry.action} —{" "}
                            <span style={{ color: entry.outcome === "success" ? "#34d399" : "#f87171" }}>
                              {entry.outcome}
                            </span>
                            <div style={{ color: "var(--text-muted)", fontSize: 10.5 }}>{entry.detail}</div>
                          </div>
                        ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* VIEW 2: DISCOVERED PRINTERS */}
        {currentTab === "discovered" && (
          <div>
            <div className="panel">
              <h2>Network Printer Auto-Discovery</h2>
              <p className="sub">
                Passive and active protocol scanning across authorized subnets. Broadcasts are strictly bounded.
              </p>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                <button
                  className="btn-blue"
                  disabled={discovering}
                  onClick={() => triggerDiscovery("mdns")}
                >
                  📡 Scan via mDNS / Bonjour
                </button>
                <button
                  className="btn-teal"
                  disabled={discovering}
                  onClick={() => triggerDiscovery("wsd")}
                >
                  🖥️ Scan via WS-Discovery (WSD / Windows)
                </button>
              </div>
              {discStatus && (
                <p style={{ marginTop: 14, color: discStatus.includes("error") ? "#f87171" : "#34d399", fontSize: 13.5 }}>
                  {discStatus}
                </p>
              )}
            </div>

            <div className="panel">
              <h2>Discovered Devices</h2>
              <table>
                <thead>
                  <tr>
                    <th>Address</th>
                    <th>Hostname / UUID</th>
                    <th>Identified Model</th>
                    <th>Discovery Mechanism</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.id}>
                      <td><strong>{d.ip_or_hostname}</strong></td>
                      <td><code>{d.hostname || "—"}</code></td>
                      <td>{d.model || "Network Printer"}</td>
                      <td>
                        <span className="pill source">{d.source || "manual"}</span>
                      </td>
                      <td>
                        <button
                          className="btn-blue btn-sm"
                          onClick={() => {
                            setSelected(d);
                            setCurrentTab("dashboard");
                          }}
                        >
                          Inspect & Assess
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {devices.length === 0 && (
                <p className="empty">No discovered devices yet. Click one of the scan buttons above.</p>
              )}
            </div>
          </div>
        )}

        {/* VIEW 3: AUDIT LOGS */}
        {currentTab === "logs" && (
          <div className="panel">
            <h2>Audit Logs</h2>
            <p className="sub">
              Complete, immutable operational log of all network operations, discovery events, and administrative changes.
            </p>
            <div style={{ marginBottom: 14 }}>
              <input
                placeholder="Filter logs by action, target, or outcome..."
                value={auditSearch}
                onChange={(e) => setAuditSearch(e.target.value)}
              />
            </div>
            <table>
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Action</th>
                  <th>Outcome</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredAudit.map((log) => (
                  <tr key={log.id}>
                    <td style={{ whiteSpace: "nowrap", fontFamily: "monospace", fontSize: 12 }}>
                      {log.timestamp.slice(0, 19).replace("T", " ")}
                    </td>
                    <td><code>{log.action}</code></td>
                    <td>
                      <span className={`pill ${log.outcome === "success" ? "success" : "failure"}`}>
                        {log.outcome}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>{log.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredAudit.length === 0 && <p className="empty">No matching audit logs found.</p>}
          </div>
        )}

        {/* VIEW 4: SETTINGS & SCOPE */}
        {currentTab === "settings" && (
          <div>
            <div className="panel">
              <h2>Authorized Network Scope (LAN Enforcement)</h2>
              <p className="sub">
                Server-side scope barrier (05-SECURITY-ARCHITECTURE.md). The backend categorically refuses any connection to targets outside these CIDRs.
              </p>
              <form onSubmit={handleAddNetwork} className="row" style={{ alignItems: "flex-end" }}>
                <div>
                  <label>CIDR Network Subnet</label>
                  <input
                    value={newCidr}
                    onChange={(e) => setNewCidr(e.target.value)}
                    placeholder="192.168.1.0/24"
                    required
                  />
                </div>
                <div>
                  <label>Description</label>
                  <input
                    value={newCidrDesc}
                    onChange={(e) => setNewCidrDesc(e.target.value)}
                    placeholder="e.g. Office Lab Printers"
                  />
                </div>
                <div>
                  <label>Route through SSH Pivot (Optional)</label>
                  <select
                    value={selectedRouteId}
                    onChange={(e) => setSelectedRouteId(e.target.value)}
                  >
                    <option value="">Direct Network Connection (No Pivot)</option>
                    {routes.map((r) => (
                      <option key={r.id} value={r.id}>{r.name} ({r.pivot_host})</option>
                    ))}
                  </select>
                </div>
                <div>
                  <button type="submit" className="btn-blue">+ Add Authorized Subnet</button>
                </div>
              </form>

              {settingsMsg && (
                <p className={settingsMsg.type === "ok" ? "success-text" : "error-text"}>
                  {settingsMsg.text}
                </p>
              )}

              <table style={{ marginTop: 18 }}>
                <thead>
                  <tr>
                    <th>CIDR Subnet</th>
                    <th>Description</th>
                    <th>Route / Pivot</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {networks.map((net) => {
                    const assignedRoute = routes.find((r) => r.id === net.route_id);
                    return (
                      <tr key={net.id}>
                        <td><strong><code>{net.cidr}</code></strong></td>
                        <td>{net.description || "—"}</td>
                        <td>
                          {assignedRoute ? (
                            <span className="pill source">SSH Pivot: {assignedRoute.name}</span>
                          ) : (
                            <span className="pill">Direct Connection</span>
                          )}
                        </td>
                        <td>
                          <button
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
              {networks.length === 0 && <p className="empty">No authorized subnets configured. Targets will be rejected by default.</p>}
            </div>

            <div className="panel">
              <h2>Network Tunnel / SSH Pivot Routes</h2>
              <p className="sub">
                Configure dual-homed pivot hosts to reach isolated or remote printer segments without changing PRET.
              </p>
              <form onSubmit={handleAddRoute}>
                <div className="row">
                  <div>
                    <label>Route Identifier Name</label>
                    <input
                      value={newRouteName}
                      onChange={(e) => setNewRouteName(e.target.value)}
                      placeholder="e.g. Pivot-Lab-Host"
                      required
                    />
                  </div>
                  <div>
                    <label>SSH Pivot Host</label>
                    <input
                      value={pivotHost}
                      onChange={(e) => setPivotHost(e.target.value)}
                      placeholder="192.168.1.10"
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
                      placeholder="pivotuser"
                      required
                    />
                  </div>
                  <div>
                    <label>Password or Private Key (Encrypted at Rest)</label>
                    <input
                      type="password"
                      value={pivotSecret}
                      onChange={(e) => setPivotSecret(e.target.value)}
                      placeholder="Enter credentials"
                      required
                    />
                  </div>
                </div>
                <br />
                <button type="submit" className="btn-teal">+ Add SSH Pivot Route</button>
              </form>

              <table style={{ marginTop: 18 }}>
                <thead>
                  <tr>
                    <th>Route Name</th>
                    <th>Pivot Host & Port</th>
                    <th>Username</th>
                    <th>Connection Test</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {routes.map((r) => (
                    <tr key={r.id}>
                      <td><strong>{r.name}</strong></td>
                      <td><code>{r.pivot_host}:{r.pivot_port}</code></td>
                      <td>{r.pivot_username}</td>
                      <td>
                        <button
                          className="btn-ghost btn-sm"
                          disabled={routeTestingId === r.id}
                          onClick={() => handleTestRoute(r.id)}
                        >
                          {routeTestingId === r.id ? "Connecting..." : "Test Connection"}
                        </button>
                        {routeTestResult[r.id] && (
                          <div style={{ fontSize: 11, marginTop: 4, color: routeTestResult[r.id].includes("Success") ? "#34d399" : "#f87171" }}>
                            {routeTestResult[r.id]}
                          </div>
                        )}
                      </td>
                      <td>
                        <button
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
          </div>
        )}

        {/* ACTIVE JOB LOG MODAL */}
        {activeJobId !== null && (
          <JobLog jobId={activeJobId} onClose={() => setActiveJobId(null)} />
        )}
      </main>

      {/* CONFIRMATION MODAL FOR DESTRUCTIVE / STATE-CHANGING OPERATIONS */}
      {pendingConfirm && selected && (
        <ConfirmModal
          device={selected}
          operation={pendingConfirm}
          onCancel={() => setPendingConfirm(null)}
          onConfirm={() => {
            runOperation(selected, pendingConfirm, true);
            setPendingConfirm(null);
          }}
        />
      )}
    </div>
  );
}
