"use client";

import { usePathname } from "next/navigation";

const pageTitles: Record<string, string> = {
  "/": "Dashboard",
  "/packets": "Packet Capture",
  "/alerts": "Alerts",
  "/rules": "Detection Rules",
};

export function Header() {
  const pathname = usePathname();
  const title = pageTitles[pathname] || "NIDS";

  return (
    <header className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900/30 px-6 py-3">
      <h2 className="text-sm font-semibold text-zinc-300">{title}</h2>
      <div className="flex items-center gap-3">
        <span className="text-xs text-zinc-600">v1.0.0</span>
      </div>
    </header>
  );
}
