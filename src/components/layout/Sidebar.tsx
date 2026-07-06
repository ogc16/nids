"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Activity, AlertTriangle, FileSearch, Server } from "lucide-react";

const navItems = [
  { href: "/", label: "Dashboard", icon: Activity },
  { href: "/packets", label: "Packets", icon: FileSearch },
  { href: "/alerts", label: "Alerts", icon: AlertTriangle },
  { href: "/assets", label: "Assets", icon: Server },
  { href: "/rules", label: "Rules", icon: Shield },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex w-56 flex-col border-r border-zinc-800 bg-zinc-900/50">
      <div className="flex items-center gap-2.5 border-b border-zinc-800 px-5 py-4">
        <Shield className="h-5 w-5 text-emerald-500" />
        <span className="text-sm font-bold text-zinc-100">NIDS</span>
      </div>
      <nav className="flex-1 space-y-1 p-3">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? "bg-emerald-600/15 text-emerald-400"
                  : "text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200"
              }`}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-zinc-800 p-4">
        <div className="flex items-center gap-2 text-xs text-zinc-600">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
          System Online
        </div>
      </div>
    </aside>
  );
}
