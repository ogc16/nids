"use client";

import { useEffect, useState } from "react";
import { Alert } from "@/lib/types";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Select } from "@/components/ui/Select";
import { downloadAsJson, downloadAsCsv } from "@/lib/export";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [localUpdates, setLocalUpdates] = useState<Record<string, Alert["status"]>>({});

  useEffect(() => {
    const es = new EventSource("/api/stream");

    es.addEventListener("alerts", (e) => {
      setAlerts(JSON.parse(e.data));
    });

    return () => es.close();
  }, []);

  const updateStatus = async (alertId: string, status: Alert["status"]) => {
    setLocalUpdates((prev) => ({ ...prev, [alertId]: status }));
    await fetch("/api/alerts", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alertId, status }),
    });
  };

  const clearAll = async () => {
    setAlerts([]);
    await fetch("/api/alerts", { method: "DELETE" });
  };

  const getStatus = (alert: Alert) => localUpdates[alert.id] || alert.status;

  const filtered = alerts.filter((a) => {
    const status = getStatus(a);
    if (filter !== "all" && status !== filter) return false;
    if (severityFilter !== "all" && a.severity !== severityFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-zinc-100">Alerts</h1>
          <p className="mt-1 text-sm text-zinc-500">
            {alerts.length} total alerts ({filtered.length} shown)
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            options={[
              { label: "All Severities", value: "all" },
              { label: "Critical", value: "critical" },
              { label: "High", value: "high" },
              { label: "Medium", value: "medium" },
              { label: "Low", value: "low" },
            ]}
          />
          <Select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            options={[
              { label: "All Statuses", value: "all" },
              { label: "New", value: "new" },
              { label: "Investigating", value: "investigating" },
              { label: "Resolved", value: "resolved" },
              { label: "Dismissed", value: "dismissed" },
            ]}
          />
          <Button variant="secondary" size="sm" onClick={() => downloadAsJson(alerts, "alerts")}>
            Export JSON
          </Button>
          <Button variant="secondary" size="sm" onClick={() => downloadAsCsv(alerts as unknown as Record<string, unknown>[], "alerts")}>
            Export CSV
          </Button>
          <Button variant="danger" size="sm" onClick={clearAll}>
            Clear All
          </Button>
        </div>
      </div>

      {filtered.length === 0 ? (
        <Card>
          <div className="flex h-48 items-center justify-center text-sm text-zinc-600">
            No alerts match the current filters.
          </div>
        </Card>
      ) : (
        <div className="space-y-2">
          {filtered.map((alert) => (
            <div
              key={alert.id}
              className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 backdrop-blur-sm"
            >
              <div className="flex items-start justify-between">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-sm font-semibold text-zinc-100">
                      {alert.title}
                    </span>
                    <Badge variant={alert.severity}>{alert.severity}</Badge>
                    <Badge variant={getStatus(alert)}>{getStatus(alert)}</Badge>
                  </div>
                  <p className="mt-1 text-sm text-zinc-400">{alert.description}</p>
                  <div className="mt-2 flex flex-wrap gap-4 text-xs text-zinc-500">
                    <span>
                      Source: <span className="font-mono text-zinc-300">{alert.sourceIp}</span>
                    </span>
                    <span>
                      Dest: <span className="font-mono text-zinc-300">{alert.destinationIp}</span>
                    </span>
                    <span>Protocol: {alert.protocol}</span>
                    <span>
                      Time: {new Date(alert.timestamp).toLocaleString()}
                    </span>
                  </div>
                </div>
                <div className="ml-4 flex shrink-0 gap-2">
                  {getStatus(alert) === "new" && (
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => updateStatus(alert.id, "investigating")}
                    >
                      Investigate
                    </Button>
                  )}
                  {getStatus(alert) === "investigating" && (
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => updateStatus(alert.id, "resolved")}
                    >
                      Resolve
                    </Button>
                  )}
                  {getStatus(alert) !== "dismissed" && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => updateStatus(alert.id, "dismissed")}
                    >
                      Dismiss
                    </Button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
