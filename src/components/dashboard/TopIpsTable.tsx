import { TrafficStats } from "@/lib/types";
import { Card } from "@/components/ui/Card";

interface TopIpsTableProps {
  ips: TrafficStats["topSourceIps"];
  ports: TrafficStats["topDestPorts"];
}

export function TopIpsTable({ ips, ports }: TopIpsTableProps) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card title="Top Source IPs" subtitle="Most active source addresses">
        {ips.length === 0 ? (
          <div className="flex h-24 items-center justify-center text-sm" style={{ color: "var(--text-faint)" }}>
            No data
          </div>
        ) : (
          <div className="space-y-1.5">
            {ips.map((item, i) => (
              <div
                key={item.ip}
                className="flex items-center justify-between rounded px-2 py-1 text-sm transition-colors"
                style={{ color: "var(--text-primary)" }}
                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "var(--bg-hover)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "transparent"; }}
              >
                <div className="flex items-center gap-2">
                  <span className="w-5 text-xs font-medium" style={{ color: "var(--text-faint)" }}>#{i + 1}</span>
                  <span className="font-mono text-xs" style={{ color: "var(--text-secondary)" }}>{item.ip}</span>
                </div>
                <span className="font-mono text-xs" style={{ color: "var(--text-muted)" }}>{item.count} pkts</span>
              </div>
            ))}
          </div>
        )}
      </Card>
      <Card title="Top Destination Ports" subtitle="Most targeted ports">
        {ports.length === 0 ? (
          <div className="flex h-24 items-center justify-center text-sm" style={{ color: "var(--text-faint)" }}>
            No data
          </div>
        ) : (
          <div className="space-y-1.5">
            {ports.map((item, i) => (
              <div
                key={item.port}
                className="flex items-center justify-between rounded px-2 py-1 text-sm transition-colors"
                style={{ color: "var(--text-primary)" }}
                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "var(--bg-hover)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "transparent"; }}
              >
                <div className="flex items-center gap-2">
                  <span className="w-5 text-xs font-medium" style={{ color: "var(--text-faint)" }}>#{i + 1}</span>
                  <span className="font-mono text-xs" style={{ color: "var(--text-secondary)" }}>{item.port}</span>
                </div>
                <span className="font-mono text-xs" style={{ color: "var(--text-muted)" }}>{item.count} pkts</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
