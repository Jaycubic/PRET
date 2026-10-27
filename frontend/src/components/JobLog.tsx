import { useEffect, useRef, useState, useMemo } from "react";
import { openJobLogSocket, api, JobResult } from "../lib/api";
import { useToast } from "./Toast";

interface JobLogProps {
  jobId: number;
  onClose: () => void;
}

interface LifecycleStep {
  stage: string;
  status: "pending" | "running" | "ok" | "warn" | "fail";
  message: string;
  timestamp: string;
}

const STAGE_ORDER = [
  { key: "checking_scope", label: "Scope Verification" },
  { key: "resolving_target", label: "Target Resolution" },
  { key: "connecting_socket", label: "Socket Transport" },
  { key: "executing_command", label: "Protocol Execution" },
  { key: "evaluating_safety", label: "Evidence Audit" },
  { key: "completed", label: "Job Finalized" },
];

export default function JobLog({ jobId, onClose }: JobLogProps) {
  const { toast } = useToast();
  const [lines, setLines] = useState<string[]>([]);
  const [stages, setStages] = useState<Record<string, LifecycleStep>>({});
  const [jobResults, setJobResults] = useState<JobResult[]>([]);
  const [isLive, setIsLive] = useState(true);
  const [autoScroll, setAutoScroll] = useState(true);
  const [isPaused, setIsPaused] = useState(false);
  const [filterText, setFilterText] = useState("");
  const [copied, setCopied] = useState(false);

  const boxRef = useRef<HTMLDivElement>(null);

  // Load historical results in case the job already completed
  useEffect(() => {
    api.jobResults(jobId)
      .then((res) => {
        setJobResults(res);
        if (res.length > 0) {
          // If we have completed results, populate timeline
          const r = res[0];
          setStages((prev) => ({
            ...prev,
            completed: {
              stage: "completed",
              status: r.status === "ok" ? "ok" : "fail",
              message: r.summary || (r.status === "ok" ? "Completed successfully" : r.error_detail),
              timestamp: new Date().toLocaleTimeString(),
            },
          }));
        }
      })
      .catch(() => {});
  }, [jobId]);

  // WebSocket Live Streaming
  useEffect(() => {
    let ws: WebSocket | null = null;
    try {
      ws = openJobLogSocket(jobId);

      ws.onopen = () => {
        setIsLive(true);
      };

      ws.onmessage = (ev) => {
        const raw = ev.data;
        if (typeof raw === "string" && raw.startsWith("{") && raw.includes("lifecycle_event")) {
          try {
            const parsed = JSON.parse(raw);
            if (parsed.type === "lifecycle_event") {
              setStages((prev) => ({
                ...prev,
                [parsed.stage]: {
                  stage: parsed.stage,
                  status: parsed.status,
                  message: parsed.message,
                  timestamp: new Date(parsed.timestamp).toLocaleTimeString(),
                },
              }));
              return;
            }
          } catch {
            // fallback to printing as text line
          }
        }

        if (!isPaused) {
          setLines((prev) => [...prev.slice(-2000), raw]);
        }
      };

      ws.onclose = () => {
        setIsLive(false);
      };

      ws.onerror = () => {
        setIsLive(false);
      };
    } catch {
      setIsLive(false);
    }

    return () => {
      if (ws) ws.close();
    };
  }, [jobId, isPaused]);

  // Auto-scroll output console
  useEffect(() => {
    if (autoScroll && boxRef.current) {
      boxRef.current.scrollTop = boxRef.current.scrollHeight;
    }
  }, [lines, autoScroll]);

  const filteredLines = useMemo(() => {
    if (!filterText.trim()) return lines;
    const q = filterText.toLowerCase();
    return lines.filter((l) => l.toLowerCase().includes(q));
  }, [lines, filterText]);

  async function handleCopyOutput() {
    const text = lines.join("\n");
    await navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success("Job console output copied to clipboard.", "Copied");
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className="modal-card" style={{ maxWidth: 840, maxHeight: "90vh", display: "flex", flexDirection: "column" }}>
        {/* HEADER */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <h3 style={{ margin: 0, fontSize: 17 }}>Job #{jobId} Execution Telemetry</h3>
            <span
              className={`pill ${isLive ? "recommended" : "source"}`}
              style={{ fontSize: 11, fontWeight: 700 }}
            >
              {isLive ? "● LIVE STREAM" : "HISTORICAL LOG"}
            </span>
          </div>
          <button type="button" className="btn-ghost btn-sm" onClick={onClose}>
            ✕ Close
          </button>
        </div>

        {/* STRUCTURED ACTION TIMELINE STEPPER */}
        <div
          style={{
            padding: "10px 14px",
            background: "var(--panel2)",
            borderRadius: 8,
            border: "1px solid var(--border)",
            marginBottom: 14,
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 8 }}>
            Action Timeline Milestones
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(110px, 1fr))", gap: 6 }}>
            {STAGE_ORDER.map((stage) => {
              const current = stages[stage.key];
              const isError = stages["error"] && stage.key === "completed";
              const isDone = current?.status === "ok";
              const isRunning = current?.status === "running";
              const isFailed = current?.status === "fail" || isError;

              const bg = isDone
                ? "rgba(52, 211, 153, 0.15)"
                : isRunning
                ? "rgba(56, 189, 248, 0.2)"
                : isFailed
                ? "rgba(248, 113, 113, 0.15)"
                : "rgba(30, 44, 74, 0.4)";

              const color = isDone
                ? "#34d399"
                : isRunning
                ? "#38bdf8"
                : isFailed
                ? "#f87171"
                : "var(--text-muted)";

              return (
                <div
                  key={stage.key}
                  style={{
                    padding: "6px 8px",
                    background: bg,
                    borderRadius: 6,
                    border: `1px solid ${color}`,
                    fontSize: 11,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontWeight: 600, color }}>{stage.label}</span>
                    <span>{isDone ? "✓" : isRunning ? "⏳" : isFailed ? "✕" : "○"}</span>
                  </div>
                  {current && (
                    <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {current.timestamp}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          {stages["error"] && (
            <div style={{ marginTop: 8, fontSize: 12, color: "#f87171" }}>
              ⚠️ Failure detail: {stages["error"].message}
            </div>
          )}
        </div>

        {/* CONSOLE CONTROLS TOOLBAR */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input
              style={{ width: 200, height: 30, fontSize: 12, padding: "2px 8px" }}
              placeholder="Search console lines..."
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
            />
            {filterText && (
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {filteredLines.length} match(es)
              </span>
            )}
          </div>

          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 12, color: "var(--text-muted)", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
              />
              Auto-Scroll
            </label>
            {isLive && (
              <button
                type="button"
                className="btn-ghost btn-sm"
                style={{ fontSize: 11, padding: "2px 8px" }}
                onClick={() => setIsPaused(!isPaused)}
              >
                {isPaused ? "▶ Resume Stream" : "⏸ Pause"}
              </button>
            )}
            <button
              type="button"
              className="btn-ghost btn-sm"
              style={{ fontSize: 11, padding: "2px 8px" }}
              onClick={handleCopyOutput}
            >
              {copied ? "✓ Copied" : "📋 Copy Console"}
            </button>
          </div>
        </div>

        {/* TERMINAL OUTPUT CONSOLE (BOUNDED SCROLLBACK) */}
        <div
          className="log-box"
          ref={boxRef}
          style={{
            flex: 1,
            minHeight: 260,
            maxHeight: 380,
            overflowY: "auto",
            background: "#080c14",
            padding: 12,
            borderRadius: 6,
            border: "1px solid var(--border)",
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
            fontSize: 12,
            lineHeight: 1.5,
          }}
        >
          {filteredLines.length === 0 ? (
            <div className="empty" style={{ padding: "40px 0", textAlign: "center", color: "var(--text-muted)" }}>
              {isLive ? "⏳ Awaiting output from execution engine..." : "No console lines captured for this job."}
            </div>
          ) : (
            filteredLines.map((l, i) => (
              <div
                key={i}
                className="logline"
                style={{
                  color: l.includes("error") || l.includes("failed") || l.includes("BLOCKED")
                    ? "#f87171"
                    : l.includes("success") || l.includes("finished: ok")
                    ? "#34d399"
                    : l.includes("established") || l.includes("opening tunnel")
                    ? "#38bdf8"
                    : "#cbd5e1",
                }}
              >
                {l}
              </div>
            ))
          )}
        </div>

        {/* COMPLETED EVIDENCE PREVIEW IF PRESENT */}
        {jobResults.length > 0 && jobResults[0].summary && (
          <div style={{ marginTop: 10, padding: "8px 12px", background: "var(--panel2)", borderRadius: 6, fontSize: 12 }}>
            <strong style={{ color: "#34d399" }}>Outcome: </strong>
            <span>{jobResults[0].summary}</span>
          </div>
        )}
      </div>
    </div>
  );
}
