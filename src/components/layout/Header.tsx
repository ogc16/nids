"use client";

import { usePathname } from "next/navigation";
import { useTheme } from "@/lib/theme-context";
import { Sun, Moon } from "lucide-react";

const pageTitles: Record<string, string> = {
  "/": "Dashboard",
  "/packets": "Packet Capture",
  "/alerts": "Alerts",
  "/rules": "Detection Rules",
};

export function Header() {
  const pathname = usePathname();
  const title = pageTitles[pathname] || "NIDS";
  const { theme, toggle } = useTheme();

  return (
    <header className="flex items-center justify-between border-b px-6 py-3" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface-alt)" }}>
      <h2 className="text-sm font-semibold" style={{ color: "var(--text-secondary)" }}>{title}</h2>
      <div className="flex items-center gap-3">
        <button
          onClick={toggle}
          className="flex h-8 w-8 items-center justify-center rounded-lg transition-colors"
          style={{ color: "var(--text-muted)" }}
          onMouseEnter={(e) => { e.currentTarget.style.color = "var(--text-primary)"; e.currentTarget.style.backgroundColor = "var(--bg-hover)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.color = "var(--text-muted)"; e.currentTarget.style.backgroundColor = "transparent"; }}
          aria-label="Toggle theme"
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
        <span className="text-xs" style={{ color: "var(--text-faint)" }}>v1.0.0</span>
      </div>
    </header>
  );
}
