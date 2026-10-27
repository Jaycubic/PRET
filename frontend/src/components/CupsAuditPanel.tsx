import { useState, useRef } from "react";
import {
  api,
  Device,
  JobResult,
  AdapterInfo,
  Operation,
  CupsQueue,
  CveFinding,
  ExploitVerifyResult,
} from "../lib/api";

interface CupsAuditPanelProps {
  device: Device;
  deviceResults: JobResult[];
  adapters: AdapterInfo[];
  onRunOperation: (device: Device, op: Operation) => void;
  onRefresh: () => void;
}

export default function CupsAuditPanel({
  device,
  deviceResults,
  adapters,
  onRunOperation,
  onRefresh,
}: CupsAuditPanelProps) {
  const [exploitLogs, setExploitLogs] = useState<string[]>([]);
  const [exploitRunning, setExploitRunning] = useState(false);
  const [exploitResult, setExploitResult] = useState<ExploitVerifyResult | null>(null);
  const [exploitError, setExploitError] = useState<string | null>(null);
  const exploitTerminalRef = useRef<HTMLDivElement>(null);
  const exploitAbortRef = useRef<AbortController | null>(null);

  const latestCups =
    deviceResults.find(
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
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button
            type="button"
            className="btn-blue btn-sm"
            onClick={() => {
              const fullAuditOp = adapters
                .find((a) => a.id === "cups_server")
                ?.operations.find((o) => o.id === "cups_full_audit");
              if (fullAuditOp) onRunOperation(device, fullAuditOp);
            }}
          >
            ⚡ Run Full CUPS Cyber Audit
          </button>
          <button
            type="button"
            className="btn-exploit"
            disabled={exploitRunning}
            onClick={() => {
              setExploitLogs([]);
              setExploitResult(null);
              setExploitError(null);
              setExploitRunning(true);
              const controller = api.exploitVerifyCups(
                device.resolved_ip || device.ip_or_hostname,
                device.port || 631,
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
                    setTimeout(onRefresh, 1000);
                  },
                  onError: (err) => {
                    setExploitError(err);
                    setExploitRunning(false);
                  },
                }
              );
              exploitAbortRef.current = controller;
            }}
          >
            {exploitRunning ? "⏳ Running Exploit Verification..." : "⚡ Real-Time Exploit Verification"}
          </button>
        </div>
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
                  PRET Exploit Verification Console — {device.resolved_ip}:{device.port || 631}
                </span>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  {exploitRunning && (
                    <button
                      type="button"
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
                  const isSuccess =
                    line.includes("| ") &&
                    (line.includes("EXPLOITABLE") ||
                      line.includes("RESPONDED") ||
                      line.includes("ACCEPTED") ||
                      line.includes("DETECTED") ||
                      line.includes("LEAKED") ||
                      line.includes("UNSANITIZED") ||
                      line.includes("CONFIRMED") ||
                      line.includes("RCE_CHAIN_CONFIRMED") ||
                      line.includes("🚨"));
                  const isWarning = line.includes("warning") || line.includes("PARTIAL") || line.includes("VERSION_VULNERABLE");
                  const isError = line.includes("ABORTED") || line.includes("error");
                  const isComplete = line.includes("VERIFICATION_COMPLETE") || line.includes("CHAIN_SYNTHESIS");

                  let statusClass = "status-running";
                  if (isSuccess) statusClass = "status-success";
                  else if (isWarning) statusClass = "status-warning";
                  else if (isError) statusClass = "status-error";
                  else if (isComplete) statusClass = "status-complete";
                  else if (line.includes("| ") && (line.includes("info") || line.includes("No ") || line.includes("not")))
                    statusClass = "status-info";

                  return (
                    <div key={i} className={`exploit-line ${isPhase ? "phase-header" : ""} ${statusClass}`}>
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
                <span style={{ color: "#475569" }}>{exploitLogs.length} events</span>
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
                        <span key={cve} className={`exploit-cve-pill ${confirmed ? "exploitable" : "safe"}`}>
                          {confirmed ? "🔓" : "🔒"} {cve}: {confirmed ? "EXPLOITABLE" : "NOT CONFIRMED"}
                        </span>
                      );
                    })}
                  </div>
                  {exploitResult.evidence.chain_exploitable && (
                    <div
                      style={{
                        marginTop: 10,
                        padding: "10px 14px",
                        background: "rgba(239, 68, 68, 0.15)",
                        border: "1px solid #ef4444",
                        borderRadius: 8,
                        color: "#f87171",
                        fontSize: 12.5,
                        fontWeight: 600,
                      }}
                    >
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
            <div
              style={{
                marginTop: 14,
                background: "rgba(30, 41, 59, 0.5)",
                border: "1px solid var(--border)",
                borderRadius: 8,
                padding: 12,
              }}
            >
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
}
