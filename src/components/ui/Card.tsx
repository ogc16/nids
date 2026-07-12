import { ReactNode } from "react";

interface CardProps {
  title?: string;
  subtitle?: string;
  children: ReactNode;
  className?: string;
  action?: ReactNode;
}

export function Card({ title, subtitle, children, className = "", action }: CardProps) {
  return (
    <div
      className={`rounded-xl border backdrop-blur-sm ${className}`}
      style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)", boxShadow: "var(--shadow-sm)" }}
    >
      {(title || action) && (
        <div className="flex items-center justify-between border-b px-5 py-4" style={{ borderColor: "var(--border-default)" }}>
          <div>
            {title && <h3 className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs" style={{ color: "var(--text-muted)" }}>{subtitle}</p>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      <div className="px-5 py-4">{children}</div>
    </div>
  );
}
