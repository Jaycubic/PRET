import React, { createContext, useContext, useState, useCallback, useMemo } from "react";

export type ToastKind = "success" | "error" | "warning" | "info";

export interface ToastItem {
  id: string;
  kind: ToastKind;
  title?: string;
  message: string;
  technicalDetails?: string;
  durationMs?: number;
}

interface ToastContextType {
  toast: {
    success: (message: string, title?: string, technicalDetails?: string) => void;
    error: (message: string, title?: string, technicalDetails?: string) => void;
    warning: (message: string, title?: string, technicalDetails?: string) => void;
    info: (message: string, title?: string) => void;
  };
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextType | null>(null);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(
    (kind: ToastKind, message: string, title?: string, technicalDetails?: string, durationMs = 5000) => {
      const id = "toast_" + Math.random().toString(36).slice(2, 9);
      const newToast: ToastItem = { id, kind, title, message, technicalDetails, durationMs };
      setToasts((prev) => [...prev, newToast]);

      if (durationMs > 0) {
        setTimeout(() => {
          dismiss(id);
        }, durationMs);
      }
    },
    [dismiss]
  );

  const toast = useMemo(
    () => ({
      success: (message: string, title?: string, technicalDetails?: string) =>
        addToast("success", message, title || "Success", technicalDetails, 4500),
      error: (message: string, title?: string, technicalDetails?: string) =>
        addToast("error", message, title || "Action Failed", technicalDetails, 7000),
      warning: (message: string, title?: string, technicalDetails?: string) =>
        addToast("warning", message, title || "Warning", technicalDetails, 5500),
      info: (message: string, title?: string) =>
        addToast("info", message, title, undefined, 4000),
    }),
    [addToast]
  );

  return (
    <ToastContext.Provider value={{ toast, dismiss }}>
      {children}
      <div
        className="toast-viewport"
        aria-live="polite"
        aria-atomic="false"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            role={t.kind === "error" ? "alert" : "status"}
            className={`toast-item toast-${t.kind}`}
          >
            <div className="toast-icon">
              {t.kind === "success" && "✓"}
              {t.kind === "error" && "⚠️"}
              {t.kind === "warning" && "⚡"}
              {t.kind === "info" && "ℹ"}
            </div>
            <div className="toast-content">
              {t.title && <div className="toast-title">{t.title}</div>}
              <div className="toast-message">{t.message}</div>
              {t.technicalDetails && (
                <details className="toast-details">
                  <summary>Technical Details</summary>
                  <pre>{t.technicalDetails}</pre>
                </details>
              )}
            </div>
            <button
              type="button"
              className="toast-close"
              aria-label="Dismiss notification"
              onClick={() => dismiss(t.id)}
            >
              ✕
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextType {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToast must be used within a ToastProvider");
  }
  return ctx;
}
