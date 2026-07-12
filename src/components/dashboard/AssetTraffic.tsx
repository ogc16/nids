import { NetworkAsset } from "@/lib/types";
import { StatusDot } from "@/components/ui/StatusDot";
import Link from "next/link";

interface AssetRow {
  asset: NetworkAsset;
  totalPackets: number;
  totalAlerts: number;
  lastSeen: number;
}

export function AssetTraffic({ assets }: { assets: AssetRow[] }) {
  const active = assets
    .filter((a) => a.totalPackets > 0)
    .sort((a, b) => b.totalPackets - a.totalPackets)
    .slice(0, 6);

  if (active.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-xs" style={{ color: "var(--text-faint)" }}>
        No asset traffic yet.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {active.map((row) => {
        const max = active[0].totalPackets;
        const pct = max > 0 ? (row.totalPackets / max) * 100 : 0;
        const isActive = Date.now() - row.lastSeen < 10000;

        return (
          <Link
            key={row.asset.id}
            href="/assets"
            className="block rounded-lg px-3 py-2 transition-colors"
            style={{ backgroundColor: "transparent" }}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "var(--bg-hover)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "transparent"; }}
          >
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 min-w-0">
                <StatusDot status={isActive ? "active" : "inactive"} />
                <span className="font-medium truncate" style={{ color: "var(--text-secondary)" }}>
                  {row.asset.name}
                </span>
                <span className="font-mono" style={{ color: "var(--text-muted)" }}>{row.asset.ip}</span>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span style={{ color: "var(--text-muted)" }}>{row.totalPackets} pkt</span>
                {row.totalAlerts > 0 && (
                  <span className="text-red-500">{row.totalAlerts} alerts</span>
                )}
              </div>
            </div>
            <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full" style={{ backgroundColor: "var(--bg-muted)" }}>
              <div
                className={`h-full rounded-full transition-all ${
                  row.totalAlerts > 0 ? "bg-red-500" : "bg-emerald-500"
                }`}
                style={{ width: `${pct}%` }}
              />
            </div>
          </Link>
        );
      })}
    </div>
  );
}
