import { useEffect, useRef, useState } from "react";
import { openJobLogSocket } from "../lib/api";

/** Streams live output for one job over /ws/jobs/{id}. Closes the socket
 * on unmount — see 07-DATA-MODEL-AND-MEMORY.md §5 on not leaving
 * listeners open past the lifetime that needs them. */
export default function JobLog({ jobId, onClose }: { jobId: number; onClose: () => void }) {
  const [lines, setLines] = useState<string[]>([]);
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const ws = openJobLogSocket(jobId);
    ws.onmessage = (ev) => setLines((prev) => [...prev.slice(-500), ev.data]);
    ws.onerror = () => setLines((prev) => [...prev, "[connection error]"]);
    return () => ws.close();
  }, [jobId]);

  useEffect(() => {
    boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight });
  }, [lines]);

  return (
    <div className="panel">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h3>Job #{jobId} — live log</h3>
        <button className="btn-ghost" onClick={onClose}>Close</button>
      </div>
      <div className="log-box" ref={boxRef}>
        {lines.length === 0 && <div className="empty">Waiting for output…</div>}
        {lines.map((l, i) => (
          <div className="logline" key={i}>{l}</div>
        ))}
      </div>
    </div>
  );
}
