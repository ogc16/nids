"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Shield, Activity, AlertTriangle, FileSearch, Server, Wifi } from "lucide-react";

const navItems = [
  { href: "/", label: "Dashboard", icon: Activity },
  { href: "/packets", label: "Packets", icon: FileSearch },
  { href: "/alerts", label: "Alerts", icon: AlertTriangle },
  { href: "/assets", label: "Assets", icon: Server },
  { href: "/network", label: "Network", icon: Wifi },
  { href: "/rules", label: "Rules", icon: Shield },
];

export function Sidebar() {
  const pathname = usePathname();
  const [ip, setIp] = useState("");

  useEffect(() => {
    fetch("/api/network")
      .then((r) => r.json())
      .then((d) => setIp(d.publicIp || d.ip))
      .catch(() => {});
  }, []);

  return (
    <aside className="flex w-56 flex-col border-r" style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface-alt)" }}>
      <div className="flex items-center gap-2.5 border-b px-5 py-4" style={{ borderColor: "var(--border-default)" }}>
        <Shield className="h-5 w-5" style={{ color: "var(--accent)" }} />
        <span className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>NIDS</span>
      </div>
      <nav className="flex-1 space-y-1 p-3">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors"
              style={{
                backgroundColor: isActive ? "var(--accent-subtle)" : "transparent",
                color: isActive ? "var(--accent)" : "var(--text-muted)",
              }}
              onMouseEnter={(e) => { if (!isActive) { e.currentTarget.style.backgroundColor = "var(--bg-hover)"; e.currentTarget.style.color = "var(--text-secondary)"; } }}
              onMouseLeave={(e) => { if (!isActive) { e.currentTarget.style.backgroundColor = "transparent"; e.currentTarget.style.color = "var(--text-muted)"; } }}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t p-4" style={{ borderColor: "var(--border-default)" }}>
        <div className="flex items-center gap-2 text-xs" style={{ color: "var(--text-faint)" }}>
          <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ backgroundColor: "var(--accent)" }} />
          System Online
        </div>
        {ip && (
          <p className="mt-1 font-mono text-[10px]" style={{ color: "var(--text-faint)" }}>{ip}</p>
        )}
      </div>
    </aside>
  );
}
