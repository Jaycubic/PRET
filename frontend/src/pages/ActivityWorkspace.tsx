import { useState } from "react";
import { Job, AuditEntry, Device } from "../lib/api";
import JobLog from "../components/JobLog";

interface ActivityWorkspaceProps {
  jobs: Job[];
  audit: AuditEntry[];
  devices: Device[];
  activeJobId: number | null;
  setActiveJobId: (jobId: number | null) => void;
  onRefresh: () => Promise<void>;
}

export default function ActivityWorkspace({
  jobs,
  audit,
  devices,
  activeJobId,
  setActiveJobId,
  onRefresh,
}: ActivityWorkspaceProps) {
  const [subTab, setSubTab] = useState<"jobs" | "audit">("jobs");
  const [auditFilter, setAuditFilter] = useState("");
  const [jobFilter, setJobFilter] = useState<"all" | "active" | "failed">("all");

  const filteredJobs = jobs.filter((job) => {
    if (jobFilter === "active") return job.status === "queued" || job.status === "running";
    if (jobFilter === "failed") return job.status === "error" || job.status === "failed";
    return true;
  });

  const filteredAudit = audit.filter((entry) => {
    if (!auditFilter.trim()) return true;
    const q = auditFilter.toLowerCase();
    return (
      entry.action.toLowerCase().includes(q) ||
      entry.outcome.toLowerCase().includes(q) ||
      entry.detail.toLowerCase().includes(q)
    );
  });

  function exportAuditJson() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(audit, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `pret_audit_export_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  return (
    <div className="activity-workspace">
      {/* HEADER & SUB-TABS */}
      <div className="panel" style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 18 }}>Activity & Operational Audit</h2>
            <p className="sub" style={{ margin: "4px 0 0" }}>
              Live job execution queues, console streams, and immutable append-only compliance logs.
            </p>
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <div className="tab-nav" style={{ margin: 0, border: "none" }}>
              <button
                type="button"
                className={`tab-btn ${subTab === "jobs" ? "active" : ""}`}
                onClick={() => setSubTab("jobs")}
              >
                ⚡ Assessment Jobs ({jobs.length})
              </button>
              <button
                type="button"
                className={`tab-btn ${subTab === "audit" ? "active" : ""}`}
                onClick={() => setSubTab("audit")}
              >
                📄 Audit Trail ({audit.length})
              </button>
            </div>
            <button type="button" className="btn-ghost btn-sm" onClick={onRefresh}>
              ↻ Refresh
            </button>
          </div>
        </div>
      </div>

      {/* SUB-TAB 1: JOBS QUEUE */}
      {subTab === "jobs" && (
        <div className="panel">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16 }}>Execution Queue & History</h3>
              <p className="sub" style={{ margin: "2px 0 0" }}>
                Each dispatched protocol operation runs as an asynchronous, monitored background job.
              </p>
            </div>

            <div className="tab-nav" style={{ margin: 0, border: "none" }}>
              <button
                type="button"
                className={`tab-btn ${jobFilter === "all" ? "active" : ""}`}
                onClick={() => setJobFilter("all")}
              >
                All ({jobs.length})
              </button>
              <button
                type="button"
                className={`tab-btn ${jobFilter === "active" ? "active" : ""}`}
                onClick={() => setJobFilter("active")}
              >
                ⏳ Active ({jobs.filter((j) => j.status === "queued" || j.status === "running").length})
              </button>
              <button
                type="button"
                className={`tab-btn ${jobFilter === "failed" ? "active" : ""}`}
                onClick={() => setJobFilter("failed")}
              >
                ❌ Failed ({jobs.filter((j) => j.status === "error" || j.status === "failed").length})
              </button>
            </div>
          </div>

          <table>
            <thead>
              <tr>
                <th>Job ID</th>
                <th>Target</th>
                <th>Adapter</th>
                <th>Operation</th>
                <th>Type</th>
                <th>Status</th>
                <th>Timeline</th>
                <th style={{ textAlign: "right" }}>Console</th>
              </tr>
            </thead>
            <tbody>
              {filteredJobs.map((j) => {
                const targetDev = devices.find((d) => d.id === j.device_id);
                const isRunning = j.status === "running" || j.status === "queued";
                const isSuccess = j.status === "succeeded";
                const isFailed = j.status === "error" || j.status === "failed";

                return (
                  <tr key={j.id}>
                    <td>
                      <strong>#{j.id}</strong>
                    </td>
                    <td>
                      {targetDev ? (
                        <span>
                          <strong>{targetDev.ip_or_hostname}</strong>
                          <span style={{ fontSize: 11, color: "var(--text-muted)", display: "block" }}>
                            {targetDev.resolved_ip}:{targetDev.port}
                          </span>
                        </span>
                      ) : (
                        <span style={{ color: "var(--text-muted)" }}>Device #{j.device_id || "—"}</span>
                      )}
                    </td>
                    <td>
                      <span className="pill">{j.adapter_id}</span>
                    </td>
                    <td>
                      <code>{j.operation_id}</code>
                    </td>
                    <td>
                      <span
                        className={`pill ${j.is_state_changing ? "failure" : "success"}`}
                        style={{ fontSize: 11 }}
                      >
                        {j.is_state_changing ? "⚠️ State-Changing" : "Read-Only"}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`pill ${
                          isRunning ? "recommended" : isSuccess ? "success" : isFailed ? "failure" : ""
                        }`}
                      >
                        {isRunning && "⏳ "}
                        {isSuccess && "✓ "}
                        {isFailed && "✕ "}
                        {j.status}
                      </span>
                    </td>
                    <td style={{ fontSize: 11.5, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                      {j.requested_at ? new Date(j.requested_at).toLocaleTimeString() : "—"}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        type="button"
                        className={isRunning ? "btn-blue btn-sm" : "btn-ghost btn-sm"}
                        onClick={() => setActiveJobId(j.id)}
                      >
                        {isRunning ? "📺 Live Stream" : "📜 View Output"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {filteredJobs.length === 0 && (
            <p className="empty">
              {jobs.length === 0
                ? "No jobs have been dispatched yet. Run an operation from the Assessments workspace."
                : "No jobs match the current filter."}
            </p>
          )}
        </div>
      )}

      {/* SUB-TAB 2: AUDIT LOG */}
      {subTab === "audit" && (
        <div className="panel">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16 }}>Immutable Compliance Audit Trail</h3>
              <p className="sub" style={{ margin: "2px 0 0" }}>
                Every action, connection attempt, and authorization check is permanently logged with timestamp and outcome.
              </p>
            </div>

            <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
              <input
                style={{ width: 260 }}
                placeholder="Filter logs by action, target, outcome..."
                value={auditFilter}
                onChange={(e) => setAuditFilter(e.target.value)}
              />
              <button type="button" className="btn-ghost btn-sm" onClick={exportAuditJson}>
                📥 Export JSON
              </button>
            </div>
          </div>

          <table>
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Action</th>
                <th>Outcome</th>
                <th>Details & Payload</th>
              </tr>
            </thead>
            <tbody>
              {filteredAudit.map((log) => (
                <tr key={log.id}>
                  <td style={{ whiteSpace: "nowrap", fontFamily: "monospace", fontSize: 12 }}>
                    {log.timestamp.slice(0, 19).replace("T", " ")}
                  </td>
                  <td>
                    <code>{log.action}</code>
                  </td>
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

      {/* LIVE / HISTORICAL JOB LOG MODAL */}
      {activeJobId !== null && (
        <JobLog jobId={activeJobId} onClose={() => setActiveJobId(null)} />
      )}
    </div>
  );
}
