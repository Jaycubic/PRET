import { useState, useEffect } from "react";
import {
  api,
  Device,
  AdapterInfo,
  Operation,
  JobResult,
} from "../lib/api";
import { useToast } from "../components/Toast";
import CupsAuditPanel from "../components/CupsAuditPanel";
import ConfirmModal from "../components/ConfirmModal";
import ActionButton from "../components/ActionButton";

interface AssessmentsWorkspaceProps {
  devices: Device[];
  selectedDevice: Device | null;
  adapters: AdapterInfo[];
  safeMode: boolean;
  onSelectDevice: (device: Device | null) => void;
  onRefresh: () => Promise<void>;
  onJobStarted: (jobId: number) => void;
}

export default function AssessmentsWorkspace({
  devices,
  selectedDevice,
  adapters,
  safeMode,
  onSelectDevice,
  onRefresh,
  onJobStarted,
}: AssessmentsWorkspaceProps) {
  const { toast } = useToast();
  const [deviceResults, setDeviceResults] = useState<JobResult[]>([]);
  const [pendingConfirm, setPendingConfirm] = useState<Operation | null>(null);
  const [runningOpId, setRunningOpId] = useState<string | null>(null);
  const [opParams, setOpParams] = useState<Record<string, Record<string, string>>>({});
  const [expandedResultId, setExpandedResultId] = useState<number | null>(null);

  // Load results for selected device
  useEffect(() => {
    if (selectedDevice) {
      api.getDeviceResults(selectedDevice.id)
        .then(setDeviceResults)
        .catch(() => setDeviceResults([]));
    } else {
      setDeviceResults([]);
    }
  }, [selectedDevice]);

  async function executeOperation(device: Device, op: Operation, confirmed: boolean) {
    const adapterId = adapters.find((a) => a.operations.some((o) => o.id === op.id))?.id;
    if (!adapterId) return;

    if (!op.read_only && safeMode) {
      toast.warning(
        "Operation blocked: Safe Mode is ACTIVE. Toggle Safe Mode OFF in the header to execute state-changing commands.",
        "Blocked by Safe Mode"
      );
      return;
    }

    setRunningOpId(op.id);
    const params = opParams[op.id] || {};

    try {
      const job = await api.createJob(device.id, adapterId, op.id, confirmed, params);
      toast.info(`Job #${job.id} (${op.display_name}) dispatched to execution engine.`, "Job Queued");
      onJobStarted(job.id);
      setTimeout(async () => {
        await onRefresh();
        if (selectedDevice) {
          api.getDeviceResults(selectedDevice.id).then(setDeviceResults).catch(() => {});
        }
      }, 1500);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to execute operation", "Execution Error");
    } finally {
      setRunningOpId(null);
    }
  }

  function handleOpClick(device: Device, op: Operation) {
    if (op.read_only) {
      executeOperation(device, op, false);
    } else {
      setPendingConfirm(op);
    }
  }

  const isCupsServer =
    selectedDevice &&
    (selectedDevice.device_type === "print_server" || selectedDevice.port === 631);

  return (
    <div className="assessments-workspace">
      {/* TARGET SELECTOR & STICKY BANNER */}
      <div className="panel" style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 14 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <h2 style={{ margin: 0, fontSize: 18 }}>Security Assessment Console</h2>
              {selectedDevice && (
                <span
                  className="pill"
                  style={{
                    background: isCupsServer ? "rgba(192, 132, 252, 0.2)" : "rgba(56, 189, 248, 0.2)",
                    color: isCupsServer ? "#c084fc" : "#38bdf8",
                    fontWeight: 700,
                  }}
                >
                  {isCupsServer ? "🖥️ CUPS Server" : "🖨️ Physical Printer"}
                </span>
              )}
            </div>
            <p className="sub" style={{ margin: "4px 0 0" }}>
              Targeted protocol audit, banner extraction, fuzzing, and vulnerability verification.
            </p>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <label style={{ fontSize: 13, fontWeight: 600, color: "var(--text-muted)", margin: 0 }}>
              Active Target:
            </label>
            <select
              style={{ minWidth: 240, height: 38 }}
              value={selectedDevice?.id || ""}
              onChange={(e) => {
                const devId = parseInt(e.target.value, 10);
                const found = devices.find((d) => d.id === devId) || null;
                onSelectDevice(found);
              }}
            >
              <option value="">-- Choose a target from inventory --</option>
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.ip_or_hostname}:{d.port} ({d.model || d.device_type || "target"})
                </option>
              ))}
            </select>
          </div>
        </div>

        {selectedDevice && (
          <div
            style={{
              marginTop: 14,
              padding: "10px 14px",
              background: "var(--panel2)",
              borderRadius: 8,
              border: "1px solid var(--border)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 12,
            }}
          >
            <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap", fontSize: 13 }}>
              <div>
                <span style={{ color: "var(--text-muted)" }}>Target: </span>
                <strong>{selectedDevice.ip_or_hostname}</strong>
              </div>
              <div>
                <span style={{ color: "var(--text-muted)" }}>Endpoint: </span>
                <code>{selectedDevice.resolved_ip}:{selectedDevice.port}</code>
              </div>
              <div>
                <span style={{ color: "var(--text-muted)" }}>Identified Model: </span>
                <span>{selectedDevice.model || "Unknown / Unprobed"}</span>
              </div>
              <div>
                <span style={{ color: "var(--text-muted)" }}>Status: </span>
                <span className={`dot ${selectedDevice.status === "online" ? "online" : "offline"}`} />
                {selectedDevice.status}
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <span
                className="pill"
                style={{
                  background: safeMode ? "rgba(52, 211, 153, 0.15)" : "rgba(248, 113, 113, 0.15)",
                  color: safeMode ? "#34d399" : "#f87171",
                  fontWeight: 600,
                  fontSize: 12,
                }}
              >
                {safeMode ? "🛡️ Safe Mode ON" : "⚠️ Safe Mode OFF"}
              </span>
            </div>
          </div>
        )}
      </div>

      {!selectedDevice ? (
        <div className="panel" style={{ textAlign: "center", padding: "40px 20px" }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>🎯</div>
          <h3 style={{ margin: "0 0 8px" }}>No Target Selected</h3>
          <p style={{ color: "var(--text-muted)", fontSize: 13, maxWidth: 480, margin: "0 auto 18px" }}>
            Select an active printer or print server target above, or pick one from the Assets inventory to reveal protocol assessment modules.
          </p>
        </div>
      ) : (
        <div>
          {/* SPECIALIZED AUDIT PANEL FOR CUPS PRINT SERVERS */}
          {isCupsServer && (
            <div style={{ marginBottom: 20 }}>
              <CupsAuditPanel
                device={selectedDevice}
                deviceResults={deviceResults}
                adapters={adapters}
                onRunOperation={handleOpClick}
                onRefresh={onRefresh}
              />
            </div>
          )}

          {/* PROTOCOL ADAPTER CATALOG */}
          <div className="row" style={{ alignItems: "flex-start" }}>
            <div style={{ flex: 2 }}>
              <div className="panel" style={{ marginBottom: 18 }}>
                <h3 style={{ margin: "0 0 6px", fontSize: 16 }}>Available Assessment Adapters & Commands</h3>
                <p className="sub" style={{ margin: "0 0 16px" }}>
                  Executes validated protocol requests via PRET engine, IPP client, or SNMP query.
                </p>

                {adapters.map((adapter) => {
                  // If viewing a CUPS server, don't clutter with duplicate raw cups_server adapter cards
                  if (isCupsServer && adapter.id === "cups_server") return null;

                  return (
                    <div
                      key={adapter.id}
                      style={{
                        marginBottom: 16,
                        padding: 14,
                        background: "var(--panel2)",
                        borderRadius: 8,
                        border: "1px solid var(--border)",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <span style={{ fontWeight: 700, fontSize: 14 }}>{adapter.display_name}</span>
                          <span className="pill" style={{ fontSize: 11 }}>{adapter.id.toUpperCase()}</span>
                        </div>
                        {!adapter.available && (
                          <span className="pill failure" style={{ fontSize: 11 }}>
                            ⚠️ Dependency Missing: {adapter.dependency_detail}
                          </span>
                        )}
                      </div>

                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 10 }}>
                        {adapter.operations.map((op) => {
                          const isDestructive = !op.read_only && (op.id.includes("destroy") || op.id.includes("fuzz"));
                          const isBlockedBySafeMode = !op.read_only && safeMode;

                          return (
                            <div
                              key={op.id}
                              style={{
                                display: "flex",
                                flexDirection: "column",
                                justifyContent: "space-between",
                                padding: 12,
                                background: "var(--panel)",
                                borderRadius: 6,
                                border: `1px solid ${
                                  op.read_only
                                    ? "rgba(52, 211, 153, 0.25)"
                                    : isDestructive
                                    ? "rgba(248, 113, 113, 0.35)"
                                    : "rgba(251, 191, 36, 0.35)"
                                }`,
                              }}
                            >
                              <div>
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6, marginBottom: 4 }}>
                                  <strong style={{ fontSize: 13 }}>{op.display_name}</strong>
                                  <span
                                    className={`pill ${
                                      op.read_only ? "success" : isDestructive ? "failure" : "recommended"
                                    }`}
                                    style={{ fontSize: 10, padding: "2px 6px" }}
                                  >
                                    {op.read_only ? "Read-Only" : isDestructive ? "Destructive" : "State-Changing"}
                                  </span>
                                </div>
                                <p style={{ fontSize: 11.5, color: "var(--text-muted)", margin: "0 0 10px", lineHeight: 1.4 }}>
                                  {op.description}
                                </p>

                                {/* OPTIONAL PARAMETER INPUTS */}
                                {op.params && op.params.length > 0 && (
                                  <div style={{ marginBottom: 10 }}>
                                    {op.params.map((param) => (
                                      <div key={param.name} style={{ marginBottom: 6 }}>
                                        <label style={{ fontSize: 11, marginBottom: 2 }}>
                                          {param.name} {param.required && "*"}
                                        </label>
                                        <input
                                          style={{ fontSize: 12, padding: "4px 8px", height: 30 }}
                                          placeholder={param.description || param.name}
                                          value={opParams[op.id]?.[param.name] || ""}
                                          onChange={(e) => {
                                            const val = e.target.value;
                                            setOpParams((prev) => ({
                                              ...prev,
                                              [op.id]: {
                                                ...(prev[op.id] || {}),
                                                [param.name]: val,
                                              },
                                            }));
                                          }}
                                        />
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>

                              <ActionButton
                                variant={op.read_only ? "teal" : isDestructive ? "red" : "blue"}
                                size="sm"
                                isLoading={runningOpId === op.id}
                                loadingText="Running..."
                                disabled={!adapter.available || isBlockedBySafeMode}
                                title={isBlockedBySafeMode ? "Blocked by Safe Mode. Turn off Safe Mode to run." : ""}
                                onClick={() => handleOpClick(selectedDevice, op)}
                                style={{ marginTop: 6 }}
                              >
                                {isBlockedBySafeMode
                                  ? "🛡️ Locked by Safe Mode"
                                  : op.read_only
                                  ? `Run ${op.display_name}`
                                  : `⚠️ Execute ${op.display_name}`}
                              </ActionButton>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* RESULTS SIDEBAR / FINDINGS EVIDENCE */}
            <div style={{ flex: 1 }}>
              <div className="panel">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                  <h3 style={{ margin: 0, fontSize: 15 }}>Historical Results ({deviceResults.length})</h3>
                  <button
                    type="button"
                    className="btn-ghost btn-sm"
                    onClick={() => {
                      if (selectedDevice) {
                        api.getDeviceResults(selectedDevice.id).then(setDeviceResults).catch(() => {});
                      }
                    }}
                  >
                    ↻
                  </button>
                </div>

                {deviceResults.length === 0 ? (
                  <p className="empty" style={{ fontSize: 12.5 }}>
                    No prior scan results recorded for this device.
                  </p>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: 600, overflowY: "auto" }}>
                    {deviceResults.map((res) => {
                      const isExpanded = expandedResultId === res.id;
                      const sevClass =
                        res.severity === "critical"
                          ? "failure"
                          : res.severity === "high"
                          ? "failure"
                          : res.severity === "medium"
                          ? "recommended"
                          : "success";

                      return (
                        <div
                          key={res.id}
                          style={{
                            padding: 10,
                            background: "var(--panel2)",
                            borderRadius: 6,
                            border: "1px solid var(--border)",
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 6 }}>
                            <div>
                              <strong style={{ fontSize: 12.5 }}>Job #{res.job_id}</strong>
                              <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: 6 }}>
                                {res.operation_id || "audit"}
                              </span>
                            </div>
                            <span className={`pill ${sevClass}`} style={{ fontSize: 10 }}>
                              {res.severity.toUpperCase()}
                            </span>
                          </div>

                          <div style={{ fontSize: 12, margin: "6px 0 4px", color: "var(--text)" }}>
                            {res.summary || "Completed operation."}
                          </div>

                          {res.error_detail && (
                            <div style={{ fontSize: 11, color: "#f87171", margin: "4px 0" }}>
                              ⚠️ {res.error_detail}
                            </div>
                          )}

                          <button
                            type="button"
                            className="btn-ghost btn-sm"
                            style={{ fontSize: 11, padding: "2px 6px", marginTop: 4 }}
                            onClick={() => setExpandedResultId(isExpanded ? null : res.id)}
                          >
                            {isExpanded ? "Hide Evidence ▲" : "View Raw Evidence ▼"}
                          </button>

                          {isExpanded && (
                            <pre
                              style={{
                                margin: "8px 0 0",
                                padding: 8,
                                background: "#0b0f19",
                                borderRadius: 4,
                                fontSize: 11,
                                overflowX: "auto",
                                maxHeight: 220,
                              }}
                            >
                              {JSON.stringify(res.evidence_json, null, 2)}
                            </pre>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CONFIRMATION MODAL FOR STATE-CHANGING / DESTRUCTIVE COMMANDS */}
      {pendingConfirm && selectedDevice && (
        <ConfirmModal
          device={selectedDevice}
          operation={pendingConfirm}
          onCancel={() => setPendingConfirm(null)}
          onConfirm={() => {
            executeOperation(selectedDevice, pendingConfirm, true);
            setPendingConfirm(null);
          }}
        />
      )}
    </div>
  );
}
