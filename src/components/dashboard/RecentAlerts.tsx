import { Alert } from "@/lib/types";
import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";

interface RecentAlertsProps {
  alerts: Alert[];
}

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };

export function RecentAlerts({ alerts }: RecentAlertsProps) {
  const sorted = [...alerts]
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])
    .slice(0, 10);

  if (sorted.length === 0) {
    return (
      <Card title="Recent Alerts" subtitle="Latest security alerts">
        <div className="flex h-32 items-center justify-center text-sm" style={{ color: "var(--text-faint)" }}>
          No alerts yet. Traffic is clean.
        </div>
      </Card>
    );
  }

  return (
    <Card title="Recent Alerts" subtitle="Latest security alerts">
      <div className="space-y-2">
        {sorted.map((alert) => (
          <div
            key={alert.id}
            className="flex items-center justify-between rounded-lg border px-3 py-2.5"
            style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface-alt)" }}
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate text-sm font-medium" style={{ color: "var(--text-secondary)" }}>
                  {alert.title}
                </span>
                <Badge variant={alert.severity}>{alert.severity}</Badge>
              </div>
              <div className="mt-0.5 text-xs" style={{ color: "var(--text-muted)" }}>
                {alert.sourceIp}:{alert.protocol} &rarr; {alert.destinationIp}
              </div>
            </div>
            <div className="ml-3 shrink-0 text-right text-xs" style={{ color: "var(--text-faint)" }}>
              {new Date(alert.timestamp).toLocaleTimeString()}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}
