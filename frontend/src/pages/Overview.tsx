import { Device, AdapterInfo, Job, AuthorizedNetwork } from "../lib/api";

interface OverviewProps {
  devices: Device[];
  adapters: AdapterInfo[];
  jobs: Job[];
  networks: AuthorizedNetwork[];
  safeMode: boolean;
  setSafeMode: (val: boolean) => void;
  onNavigate: (tab: string) => void;
  onSelectDevice: (device: Device) => void;
}

export default function Overview({
  devices,
  adapters,
  jobs,
  networks,
  safeMode,
  setSafeMode,
  onNavigate,
  onSelectDevice,
}: OverviewProps) {
  const stats = {
    total: devices.length,
    printers: devices.filter((d) => d.device_type !== "print_server" && d.port !== 631).length,
    cupsServers: devices.filter((d) => d.device_type === "print_server" || d.port === 631).length,
    online: devices.filter((d) => d.status !== "offline").length,
    activeAdapters: adapters.filter((a) => a.available).length,
    totalAdapters: adapters.length,
    authorizedCidrs: networks.length,
  };

  // Find assets needing attention (offline, or model containing warning/vulnerable keywords)
  const assetsNeedingAttention = devices.filter(
    (d) => d.status === "offline" || (d.model && d.model.toLowerCase().includes("vulnerable"))
  );

  const recentJobs = jobs.slice(0, 5);

  return (
    <div className="overview-workspace">
      {/* SCOPE HEALTH BANNER */}
      {networks.length === 0 && (
        <div className="status-banner banner-warning" role="alert" style={{ marginBottom: 18 }}>
          <div className="banner-icon">⚠️</div>
          <div className="banner-body">
            <strong>Zero Authorized Networks Configured:</strong>
            <p style={{ margin: "4px 0 0" }}>
              The PRET engine strictly enforces LAN scope barriers. You must authorize at least one CIDR subnet in Settings before assessing targets.
            </p>
          </div>
          <button
            type="button"
            className="btn-ghost btn-sm"
            onClick={() => onNavigate("settings")}
            style={{ alignSelf: "center", whiteSpace: "nowrap" }}
          >
            ⚙️ Configure Scope
          </button>
        </div>
      )}

      {/* HEADER WITH SAFE MODE CONTROLLER */}
      <div className="panel" style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <h2 style={{ margin: 0 }}>Fleet Security Overview</h2>
              <span className="pill" style={{ background: "rgba(56, 189, 248, 0.15)", color: "#38bdf8", fontWeight: 600 }}>
                Enterprise Scope
              </span>
            </div>
            <p className="sub" style={{ margin: "6px 0 0" }}>
              Continuous vulnerability posture, protocol adapter availability, and live execution telemetry.
            </p>
          </div>
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              background: "var(--panel2)",
              padding: "10px 16px",
              borderRadius: 8,
              border: `1px solid ${safeMode ? "rgba(52, 211, 153, 0.4)" : "rgba(248, 113, 113, 0.4)"}`,
              cursor: "pointer",
            }}
          >
            <input
              type="checkbox"
              checked={safeMode}
              onChange={(e) => setSafeMode(e.target.checked)}
              style={{ width: 18, height: 18, cursor: "pointer" }}
            />
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: safeMode ? "#34d399" : "#f87171" }}>
                {safeMode ? "🛡️ Safe Mode ACTIVE" : "⚠️ Safe Mode DISENGAGED"}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {safeMode ? "Destructive actions blocked" : "Confirmation required for state-changing ops"}
              </div>
            </div>
          </label>
        </div>
      </div>

      {/* KPI METRIC CARDS */}
      <div className="stats" style={{ marginBottom: 20 }}>
        <div className="stat" onClick={() => onNavigate("assets")} style={{ cursor: "pointer" }}>
          <div className="pill">Total Assets</div>
          <div className="n">{stats.total}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>Registered targets</div>
        </div>
        <div className="stat" onClick={() => onNavigate("assets")} style={{ cursor: "pointer" }}>
          <div className="pill">🖨️ Physical Printers</div>
          <div className="n" style={{ color: "#38bdf8" }}>{stats.printers}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>Port 9100 / IPP / SNMP</div>
        </div>
        <div className="stat" onClick={() => onNavigate("assets")} style={{ cursor: "pointer" }}>
          <div className="pill">🖥️ CUPS Servers</div>
          <div className="n" style={{ color: "#c084fc" }}>{stats.cupsServers}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>Port 631 / cupsd daemon</div>
        </div>
        <div className="stat">
          <div className="pill">Reachable Now</div>
          <div className="n" style={{ color: "#34d399" }}>{stats.online}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>Responding to probe</div>
        </div>
        <div className="stat" onClick={() => onNavigate("assessments")} style={{ cursor: "pointer" }}>
          <div className="pill">Protocol Adapters</div>
          <div className="n" style={{ color: "#fbbf24" }}>{stats.activeAdapters} / {stats.totalAdapters}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>PJL, PS, IPP, SNMP, CUPS</div>
        </div>
      </div>

      {/* TWO-COLUMN LOWER SECTION */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", gap: 18 }}>
        {/* ASSETS ATTENTION CARD */}
        <div className="panel">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h3 style={{ margin: 0, fontSize: 15 }}>⚠️ Assets Needing Attention</h3>
            <button
              type="button"
              className="btn-ghost btn-sm"
              onClick={() => onNavigate("assets")}
            >
              View All Assets →
            </button>
          </div>
          {assetsNeedingAttention.length === 0 ? (
            <div style={{ padding: "20px 0", textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
              ✅ All registered targets are currently online and responding normally.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {assetsNeedingAttention.map((d) => (
                <div
                  key={d.id}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "10px 14px",
                    background: "var(--panel2)",
                    borderRadius: 8,
                    border: "1px solid var(--border)",
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{d.ip_or_hostname}</div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      {d.device_type === "print_server" ? "🖥️ CUPS Server" : "🖨️ Printer"} • Port {d.port} • Status:{" "}
                      <span style={{ color: d.status === "offline" ? "#f87171" : "#fbbf24" }}>{d.status}</span>
                    </div>
                  </div>
                  <button
                    type="button"
                    className="btn-ghost btn-sm"
                    onClick={() => {
                      onSelectDevice(d);
                      onNavigate("assessments");
                    }}
                  >
                    Inspect
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* RECENT JOBS & TELEMETRY CARD */}
        <div className="panel">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h3 style={{ margin: 0, fontSize: 15 }}>⚡ Active & Recent Assessments</h3>
            <button
              type="button"
              className="btn-ghost btn-sm"
              onClick={() => onNavigate("activity")}
            >
              View Full Activity →
            </button>
          </div>
          {recentJobs.length === 0 ? (
            <div style={{ padding: "20px 0", textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
              No assessment jobs have been executed yet. Select a target in Assessments to run audits.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {recentJobs.map((j) => (
                <div
                  key={j.id}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "8px 12px",
                    background: "var(--panel2)",
                    borderRadius: 8,
                    border: "1px solid var(--border)",
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>
                      Job #{j.id}: <code>{j.operation_id}</code>
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      Adapter: {j.adapter_id} {j.is_state_changing && "• ⚠️ State-Changing"}
                    </div>
                  </div>
                  <span
                    className={`pill ${
                      j.status === "succeeded"
                        ? "success"
                        : j.status === "running"
                        ? "recommended"
                        : j.status === "error"
                        ? "failure"
                        : ""
                    }`}
                  >
                    {j.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* QUICK WORKFLOW SHORTCUTS */}
      <div className="panel" style={{ marginTop: 18 }}>
        <h3 style={{ margin: "0 0 12px", fontSize: 14 }}>🚀 Quick Security Workflows</h3>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <button
            type="button"
            className="btn-blue"
            onClick={() => onNavigate("assets")}
          >
            + Add / Scan Target
          </button>
          <button
            type="button"
            className="btn-teal"
            onClick={() => onNavigate("assessments")}
          >
            🎯 Run Security Assessment
          </button>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => onNavigate("findings")}
          >
            🧠 Findings & Intelligence
          </button>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => onNavigate("settings")}
          >
            ⚙️ Authorized Scope & Pivots
          </button>
        </div>
      </div>
    </div>
  );
}
