import { useState } from "react";
import type { ActionStatus } from "../lib/api";

interface InlineStatusBannerProps {
  status: ActionStatus;
  title?: string;
  message: string;
  nextStep?: string;
  technicalMessage?: string;
  onDismiss?: () => void;
  style?: React.CSSProperties;
}

export default function InlineStatusBanner({
  status,
  title,
  message,
  nextStep,
  technicalMessage,
  onDismiss,
  style,
}: InlineStatusBannerProps) {
  const [showTech, setShowTech] = useState(false);

  if (status === "idle") return null;

  const isSuccess = status === "succeeded";
  const isError = status === "failed" || status === "timeout";
  const isWarning = status === "blocked" || status === "partial" || status === "unavailable" || status === "offline_fallback";
  const isSubmitting = status === "submitting" || status === "validating" || status === "queued" || status === "running";

  const statusClass = isSuccess
    ? "banner-success"
    : isError
    ? "banner-error"
    : isWarning
    ? "banner-warning"
    : isSubmitting
    ? "banner-info is-submitting"
    : "banner-info";

  const icon = isSuccess
    ? "✓"
    : isError
    ? "⚠️"
    : isWarning
    ? "⚡"
    : "⏳";

  return (
    <div className={`inline-banner ${statusClass}`} style={style} role="status">
      <div className="banner-icon">{icon}</div>
      <div className="banner-body">
        {title && <div className="banner-title">{title}</div>}
        <div className="banner-message">{message}</div>
        {nextStep && (
          <div className="banner-next-step">
            <strong>Next step:</strong> {nextStep}
          </div>
        )}
        {technicalMessage && (
          <div className="banner-tech-toggle">
            <button
              type="button"
              className="btn-link"
              onClick={() => setShowTech((prev) => !prev)}
            >
              {showTech ? "Hide diagnostic details ▲" : "View diagnostic details ▼"}
            </button>
            {showTech && (
              <pre className="banner-tech-details">{technicalMessage}</pre>
            )}
          </div>
        )}
      </div>
      {onDismiss && (
        <button
          type="button"
          className="banner-close"
          aria-label="Dismiss banner"
          onClick={onDismiss}
        >
          ✕
        </button>
      )}
    </div>
  );
}
