import { useState, useEffect, useRef } from "react";
import type { Device, Operation } from "../lib/api";

/**
 * UI half of 05-SECURITY-ARCHITECTURE.md §9's confirmation requirement.
 * Requires the operator to type the device's IP before the Confirm
 * button enables — not a bare "OK" click — and the backend independently
 * refuses the job without confirm=true regardless of what this modal does.
 */
export default function ConfirmModal({
  device,
  operation,
  onConfirm,
  onCancel,
}: {
  device: Device;
  operation: Operation;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [typed, setTyped] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const matches = typed.trim() === device.ip_or_hostname;

  useEffect(() => {
    inputRef.current?.focus();
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        onCancel();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onCancel]);

  return (
    <div
      className="modal-bg"
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-modal-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div className="modal confirm-modal-danger">
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 20 }}>⚠️</span>
          <h3 id="confirm-modal-title" style={{ margin: 0, color: "#f87171" }}>
            State-Changing Action: {operation.display_name}
          </h3>
        </div>
        <p style={{ margin: "10px 0" }}>
          This operation can modify printer non-volatile configuration, storage, or runtime state on{" "}
          <code style={{ background: "rgba(239, 68, 68, 0.2)", color: "#fca5a5", padding: "2px 6px", borderRadius: 4 }}>
            {device.ip_or_hostname}
          </code>
          .
        </p>
        <p style={{ fontSize: 13, color: "var(--text-muted)", margin: "6px 0 14px" }}>
          <strong>Operation Detail:</strong> {operation.description}
        </p>
        <div style={{ background: "rgba(0,0,0,0.3)", padding: 12, borderRadius: 8, marginBottom: 16, border: "1px solid var(--border)" }}>
          <label style={{ display: "block", fontSize: 12, fontWeight: 600, marginBottom: 6, color: "var(--text)" }}>
            To confirm this destructive action, type the target IP address exactly (<code>{device.ip_or_hostname}</code>):
          </label>
          <input
            ref={inputRef}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={device.ip_or_hostname}
            style={{ width: "100%", fontFamily: "JetBrains Mono, monospace" }}
          />
        </div>
        <div className="modal-actions" style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
          <button type="button" className="btn-ghost" onClick={onCancel}>
            Cancel (Esc)
          </button>
          <button
            type="button"
            className="btn-red"
            disabled={!matches}
            onClick={onConfirm}
            title={matches ? "Confirm and queue operation" : `Type ${device.ip_or_hostname} to enable`}
          >
            Confirm & Execute Operation
          </button>
        </div>
      </div>
    </div>
  );
}
