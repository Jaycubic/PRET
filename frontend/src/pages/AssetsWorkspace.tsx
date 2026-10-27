import { useState } from "react";
import {
  api,
  Device,
  ProbeResult,
} from "../lib/api";
import { useToast } from "../components/Toast";
import ActionButton from "../components/ActionButton";

interface AssetsWorkspaceProps {
  devices: Device[];
  selectedDevice: Device | null;
  onSelectDevice: (device: Device | null) => void;
  onNavigateToAssessments: (device: Device) => void;
  onRefresh: () => Promise<void>;
}

export default function AssetsWorkspace({
  devices,
  selectedDevice,
  onSelectDevice,
  onNavigateToAssessments,
  onRefresh,
}: AssetsWorkspaceProps) {
  const { toast } = useToast();

  // Search & Filter
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<"all" | "printer" | "print_server">("all");

  // Add Target Form
  const [ip, setIp] = useState("");
  const [port, setPort] = useState("9100");
  const [targetKind, setTargetKind] = useState<"printer" | "cups_server">("printer");
  const [detectedModel, setDetectedModel] = useState("");
  const [isAdding, setIsAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  // Auto-Probe State
  const [probing, setProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  // CUPS Direct Investigation
  const [investigatingCups, setInvestigatingCups] = useState(false);

  // Discovery State
  const [discovering, setDiscovering] = useState(false);
  const [discStatus, setDiscStatus] = useState<string | null>(null);

  // Delete device confirmation modal
  const [deviceToDelete, setDeviceToDelete] = useState<Device | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Handlers
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
      toast.info(
        `Open Ports: ${res.open_ports.join(", ")} | ${res.summary}`,
        `Port Scan: ${res.ip}`
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Port probe failed";
      setProbeError(msg);
      toast.error(msg, "Port Probe Error");
    } finally {
      setProbing(false);
    }
  }

  async function handleAddDevice() {
    if (!ip.trim()) return;
    setAddError(null);
    setIsAdding(true);
    const parsedPort = parseInt(port, 10) || (targetKind === "cups_server" ? 631 : 9100);
    const devType = targetKind === "cups_server" ? "print_server" : "printer";
    try {
      const dev = await api.addDevice(ip.trim(), parsedPort, devType, detectedModel || undefined);
      setIp("");
      setProbeResult(null);
      setDetectedModel("");
      await onRefresh();
      onSelectDevice(dev);
      toast.success(`Target ${dev.ip_or_hostname}:${dev.port} added to scope.`, "Target Added");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to add device";
      setAddError(msg);
      toast.error(msg, "Add Target Refused");
    } finally {
      setIsAdding(false);
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
      setProbeResult(null);
      setDetectedModel("");
      await onRefresh();
      onSelectDevice(resp.device);
      toast.success(`Full cyber audit completed for ${resp.device.ip_or_hostname}.`, "Investigation Complete");
      onNavigateToAssessments(resp.device);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "CUPS investigation failed";
      setAddError(msg);
      toast.error(msg, "Investigation Error");
    } finally {
      setInvestigatingCups(false);
    }
  }

  async function triggerDiscovery(type: "mdns" | "wsd") {
    setDiscovering(true);
    setDiscStatus(`Scanning local network via ${type.toUpperCase()}...`);
    try {
      const res = type === "mdns" ? await api.runMdnsDiscovery() : await api.runWsdDiscovery();
      const count = (res.found_services ?? res.found_devices) || 0;
      const statusText = `Discovered ${count} device(s). Added ${res.added_devices.length} in-scope; skipped ${res.skipped_out_of_scope.length} out-of-scope.`;
      setDiscStatus(statusText);
      toast.info(statusText, "Discovery Result");
      await onRefresh();
    } catch (err) {
      const errText = `Discovery error: ${err instanceof Error ? err.message : "Failed"}`;
      setDiscStatus(errText);
      toast.error(errText, "Discovery Error");
    } finally {
      setDiscovering(false);
    }
  }

  async function handleProbeExisting(dev: Device) {
    try {
      const res = await api.probeDevice(dev.id);
      onSelectDevice(res.device);
      await onRefresh();
      toast.info(
        `Open Ports: ${res.probe.open_ports.join(", ")} | ${res.probe.summary}`,
        `Port Scan: ${dev.ip_or_hostname}`
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Device probe failed", "Scan Error");
    }
  }

  async function handleDeleteConfirmed() {
    if (!deviceToDelete) return;
    setIsDeleting(true);
    try {
      await api.deleteDevice(deviceToDelete.id);
      toast.success(`Device ${deviceToDelete.ip_or_hostname} removed from inventory.`, "Target Deleted");
      if (selectedDevice?.id === deviceToDelete.id) {
        onSelectDevice(null);
      }
      setDeviceToDelete(null);
      await onRefresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete device", "Delete Error");
    } finally {
      setIsDeleting(false);
    }
  }

  const filteredDevices = devices.filter((d) => {
    // Type filter
    if (filterType === "printer" && (d.device_type === "print_server" || d.port === 631)) return false;
    if (filterType === "print_server" && d.device_type !== "print_server" && d.port !== 631) return false;

    // Search query filter
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      d.ip_or_hostname.toLowerCase().includes(q) ||
      d.resolved_ip.toLowerCase().includes(q) ||
      (d.model && d.model.toLowerCase().includes(q)) ||
      (d.hostname && d.hostname.toLowerCase().includes(q))
    );
  });

  return (
    <div className="assets-workspace">
      {/* ADD / AUTO-PROBE CARD */}
      <div className="panel" style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, marginBottom: 14 }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 18 }}>Add Target to Assessment Inventory</h2>
            <p className="sub" style={{ margin: "4px 0 0" }}>
              Specify a network target. Target IP must reside in an authorized CIDR subnet.
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
              🖨️ Hardware Printer (Port 9100 / RAW)
            </button>
            <button
              type="button"
              className={targetKind === "cups_server" ? "active" : ""}
              onClick={() => {
                setTargetKind("cups_server");
                setPort("631");
              }}
            >
              🖥️ CUPS Print Server (Port 631 / IPP)
            </button>
          </div>
        </div>

        <div className="row" style={{ alignItems: "flex-end" }}>
          <div style={{ flex: 3 }}>
            <label>IP Address / Hostname</label>
            <input
              value={ip}
              onChange={(e) => {
                setIp(e.target.value);
                if (probeResult) setProbeResult(null);
              }}
              placeholder={targetKind === "cups_server" ? "172.16.159.5 (CUPS Host)" : "172.16.159.5"}
            />
          </div>
          <div style={{ flex: 1 }}>
            <label>Port</label>
            <input
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder={targetKind === "cups_server" ? "631" : "9100"}
            />
          </div>
          <ActionButton
            variant="ghost"
            isLoading={probing}
            loadingText="Probing Ports..."
            disabled={!ip.trim()}
            onClick={handleProbeTarget}
            style={{ height: 38, marginBottom: 1, whiteSpace: "nowrap" }}
          >
            🔍 Auto-Scan Ports
          </ActionButton>
        </div>

        {/* PROBE RESULTS WITH INTERACTIVE PORT PILLS */}
        {probeResult && (
          <div className="probe-results-card" style={{ marginTop: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: "#38bdf8" }}>
                🔍 Fingerprint Results for {probeResult.ip}:
              </div>
              {probeResult.detected_model && (
                <span className="pill" style={{ background: "rgba(56, 189, 248, 0.2)", color: "#38bdf8", fontWeight: 700 }}>
                  Model: {probeResult.detected_model}
                </span>
              )}
            </div>
            <p style={{ margin: "6px 0 10px", fontSize: 12.5, color: "var(--text-muted)" }}>
              {probeResult.summary}
            </p>
            <div style={{ fontSize: 11.5, color: "var(--text-muted)", marginBottom: 6, fontWeight: 600 }}>
              Detected Open Ports (Click any port pill to bind it):
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
                  {svc.is_recommended && <span style={{ color: "#34d399", fontSize: 10, fontWeight: 700 }}>★ Recommended</span>}
                  {svc.banner && (
                    <span style={{ fontSize: 10, color: "var(--text-muted)", maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      ({svc.banner})
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>
        )}

        {probeError && <p className="error-text" style={{ marginTop: 10 }}>⚠️ {probeError}</p>}

        <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 14, flexWrap: "wrap" }}>
          {targetKind === "cups_server" ? (
            <>
              <ActionButton
                variant="blue"
                isLoading={investigatingCups}
                loadingText="Auditing CUPS Server..."
                disabled={!ip.trim()}
                onClick={handleInvestigateCups}
              >
                🛡️ Investigate CUPS Server (Cyber Audit)
              </ActionButton>
              <ActionButton
                variant="ghost"
                isLoading={isAdding}
                loadingText="Adding..."
                disabled={!ip.trim()}
                onClick={handleAddDevice}
              >
                + Register Target Only
              </ActionButton>
              <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                Runs CVE chain evaluation, admin auth check, and hosted queue enumeration.
              </span>
            </>
          ) : (
            <ActionButton
              variant="blue"
              isLoading={isAdding}
              loadingText="Adding..."
              disabled={!ip.trim()}
              onClick={handleAddDevice}
            >
              + Add Target to Scope
            </ActionButton>
          )}
        </div>
        {addError && <p className="error-text" style={{ marginTop: 8 }}>⚠️ {addError}</p>}
      </div>

      {/* NETWORK DISCOVERY BUTTONS */}
      <div className="panel" style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 15 }}>📡 Subnet Protocol Discovery</h3>
            <p className="sub" style={{ margin: "2px 0 0" }}>
              Passive and active discovery across authorized CIDRs. Strictly bounded to your LAN scope.
            </p>
          </div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <ActionButton
              variant="blue"
              isLoading={discovering}
              loadingText="Scanning mDNS..."
              onClick={() => triggerDiscovery("mdns")}
            >
              📡 mDNS / Bonjour
            </ActionButton>
            <ActionButton
              variant="teal"
              isLoading={discovering}
              loadingText="Scanning WSD..."
              onClick={() => triggerDiscovery("wsd")}
            >
              🖥️ WS-Discovery (Windows)
            </ActionButton>
          </div>
        </div>
        {discStatus && (
          <p style={{ marginTop: 10, color: discStatus.includes("error") ? "#f87171" : "#34d399", fontSize: 13 }}>
            {discStatus}
          </p>
        )}
      </div>

      {/* REGISTERED ASSETS TABLE WITH SEARCH & FILTER */}
      <div className="panel">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 12 }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 18 }}>Registered Assets ({devices.length})</h2>
            <p className="sub" style={{ margin: "4px 0 0" }}>
              Printers and print servers discovered or manually registered.
            </p>
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            {/* Search Input */}
            <input
              style={{ width: 220 }}
              placeholder="Search by IP, model, name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />

            {/* Type Filter Buttons */}
            <div className="tab-nav" style={{ margin: 0, border: "none" }}>
              <button
                type="button"
                className={`tab-btn ${filterType === "all" ? "active" : ""}`}
                onClick={() => setFilterType("all")}
              >
                All ({devices.length})
              </button>
              <button
                type="button"
                className={`tab-btn ${filterType === "printer" ? "active" : ""}`}
                onClick={() => setFilterType("printer")}
              >
                🖨️ Printers ({devices.filter((d) => d.device_type !== "print_server" && d.port !== 631).length})
              </button>
              <button
                type="button"
                className={`tab-btn ${filterType === "print_server" ? "active" : ""}`}
                onClick={() => setFilterType("print_server")}
              >
                🖥️ CUPS ({devices.filter((d) => d.device_type === "print_server" || d.port === 631).length})
              </button>
            </div>
          </div>
        </div>

        <table>
          <thead>
            <tr>
              <th>Target Address</th>
              <th>Type</th>
              <th>Resolved Endpoint</th>
              <th>Model / Identification</th>
              <th>Status</th>
              <th>Discovery Source</th>
              <th style={{ textAlign: "right" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredDevices.map((d) => {
              const isSelected = selectedDevice?.id === d.id;
              const isServer = d.device_type === "print_server" || d.port === 631;
              return (
                <tr
                  key={d.id}
                  className={`devrow ${isSelected ? "selected" : ""}`}
                  onClick={() => onSelectDevice(d)}
                >
                  <td>
                    <strong>{d.ip_or_hostname}</strong>
                  </td>
                  <td>
                    {isServer ? (
                      <span className="badge-server">🖥️ Print Server</span>
                    ) : (
                      <span className="badge-printer">🖨️ Printer</span>
                    )}
                  </td>
                  <td>
                    <code>{d.resolved_ip}:{d.port}</code>
                  </td>
                  <td>
                    {d.model || d.hostname || (isServer ? "CUPS Server" : "Generic Network Printer")}
                  </td>
                  <td>
                    <span className={`dot ${d.status === "online" ? "online" : d.status === "offline" ? "offline" : "unknown"}`} />
                    {d.status}
                  </td>
                  <td>
                    <span className="pill">{d.source || "manual"}</span>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                      <button
                        type="button"
                        className="btn-ghost btn-sm"
                        title="Quick port scan and model grab"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleProbeExisting(d);
                        }}
                      >
                        🔍 Probe
                      </button>
                      <button
                        type="button"
                        className="btn-blue btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectDevice(d);
                          onNavigateToAssessments(d);
                        }}
                      >
                        🎯 Assess
                      </button>
                      <button
                        type="button"
                        className="btn-red btn-sm"
                        title="Remove device from inventory"
                        onClick={(e) => {
                          e.stopPropagation();
                          setDeviceToDelete(d);
                        }}
                      >
                        ✕
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {filteredDevices.length === 0 && (
          <p className="empty">
            {devices.length === 0
              ? "No network targets registered yet. Add one above or trigger subnet discovery."
              : "No devices match the current filter or search criteria."}
          </p>
        )}
      </div>

      {/* DELETE CONFIRMATION MODAL */}
      {deviceToDelete && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-card" style={{ maxWidth: 440 }}>
            <h3 style={{ margin: "0 0 8px", color: "#f87171" }}>Remove Target from Scope?</h3>
            <p style={{ margin: "0 0 16px", fontSize: 13, color: "var(--text-muted)" }}>
              Are you sure you want to delete <strong>{deviceToDelete.ip_or_hostname}</strong> (
              {deviceToDelete.resolved_ip}:{deviceToDelete.port}) from your registered targets inventory?
            </p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
              <button
                type="button"
                className="btn-ghost btn-sm"
                onClick={() => setDeviceToDelete(null)}
                disabled={isDeleting}
              >
                Cancel
              </button>
              <ActionButton
                variant="red"
                isLoading={isDeleting}
                loadingText="Removing..."
                onClick={handleDeleteConfirmed}
              >
                Confirm Delete
              </ActionButton>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
