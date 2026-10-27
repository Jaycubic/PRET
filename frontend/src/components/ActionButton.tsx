import React from "react";

interface ActionButtonProps {
  onClick?: (e: React.MouseEvent<HTMLButtonElement>) => void | Promise<void>;
  loading?: boolean;
  isLoading?: boolean;
  disabled?: boolean;
  loadingText?: string;
  variant?: "primary" | "ghost" | "danger" | "teal" | "warning" | "blue" | "red";
  size?: "sm" | "md" | "lg";
  type?: "button" | "submit" | "reset";
  className?: string;
  style?: React.CSSProperties;
  title?: string;
  children: React.ReactNode;
}

export default function ActionButton({
  onClick,
  loading = false,
  isLoading,
  disabled = false,
  loadingText,
  variant = "primary",
  size,
  type = "button",
  className = "",
  style,
  title,
  children,
}: ActionButtonProps) {
  const isBusy = isLoading ?? loading;

  const variantClass =
    variant === "primary" || variant === "blue"
      ? "btn-blue"
      : variant === "danger" || variant === "red"
      ? "btn-red"
      : variant === "teal"
      ? "btn-teal"
      : variant === "warning"
      ? "btn-amber"
      : "btn-ghost";

  const sizeClass = size === "sm" ? "btn-sm" : "";

  return (
    <button
      type={type}
      disabled={disabled || isBusy}
      aria-busy={isBusy}
      className={`action-btn ${variantClass} ${sizeClass} ${isBusy ? "is-loading" : ""} ${className}`}
      onClick={onClick}
      style={style}
      title={title}
    >
      {loading ? (
        <span className="action-btn-spinner-content">
          <span className="spinner-dot" aria-hidden="true" />
          {loadingText || children}
        </span>
      ) : (
        children
      )}
    </button>
  );
}
