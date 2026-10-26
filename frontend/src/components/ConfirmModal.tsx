import { useState } from "react";
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
  const matches = typed.trim() === device.ip_or_hostname;

  return (
    <div className="modal-bg">
      <div className="modal">
        <h3>Confirm: {operation.display_name}</h3>
        <p>
          This is a <strong>state-changing</strong> operation on{" "}
          <code>{device.ip_or_hostname}</code>. {operation.description}
        </p>
        <p className="sub">Type the device address to confirm:</p>
        <input
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={device.ip_or_hostname}
        />
        <div className="modal-actions">
          <button className="btn-ghost" onClick={onCancel}>
            Cancel
          </button>
          <button className="btn-red" disabled={!matches} onClick={onConfirm}>
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}
