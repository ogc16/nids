"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { TrafficStats, Alert, TimeRange } from "@/lib/types";
import { StatsCards } from "@/components/dashboard/StatsCards";
import { TrafficChart } from "@/components/dashboard/TrafficChart";
import { RecentAlerts } from "@/components/dashboard/RecentAlerts";
import { ProtocolPieChart } from "@/components/dashboard/ProtocolPieChart";
import { TopIpsTable } from "@/components/dashboard/TopIpsTable";
import { Card } from "@/components/ui/Card";
import { Select } from "@/components/ui/Select";
import { StatusDot } from "@/components/ui/StatusDot";

export default function Dashboard() {
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [timeRange, setTimeRange] = useState<TimeRange>("1m");
  const [isRunning, setIsRunning] = useState(true);
  const [packetCount, setPacketCount] = useState(0);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, alertsRes] = await Promise.all([
        fetch(`/api/stats?range=${timeRange}`),
        fetch("/api/alerts"),
      ]);
      const statsData: TrafficStats = await statsRes.json();
      const alertsData: Alert[] = await alertsRes.json();
      setStats(statsData);
      setAlerts(alertsData);
    } catch {
      // Ignore fetch errors during development
    }
  }, [timeRange]);

  useEffect(() => {
    fetchData();
    if (pollingRef.current) clearInterval(pollingRef.current);
    if (isRunning) {
      pollingRef.current = setInterval(fetchData, 2000);
    }
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [fetchData, isRunning]);

  useEffect(() => {
    if (!isRunning) return;
    const interval = setInterval(async () => {
      try {
        const res = await fetch("/api/packets", { method: "POST" });
        const data = await res.json();
        setPacketCount((c) => c + data.count);
      } catch {
        // Ignore
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [isRunning]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-zinc-100">Network Dashboard</h1>
          <p className="mt-1 text-sm text-zinc-500">
            Real-time network traffic monitoring and intrusion detection
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-sm text-zinc-400">
            <StatusDot status={isRunning ? "active" : "inactive"} />
            {isRunning ? "Monitoring" : "Paused"}
          </div>
          <button
            onClick={() => setIsRunning(!isRunning)}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
              isRunning
                ? "bg-red-600/20 text-red-400 hover:bg-red-600/30"
                : "bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30"
            }`}
          >
            {isRunning ? "Stop" : "Start"}
          </button>
          <Select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value as TimeRange)}
            options={[
              { label: "Last 1 min", value: "1m" },
              { label: "Last 5 min", value: "5m" },
              { label: "Last 15 min", value: "15m" },
              { label: "Last 1 hour", value: "1h" },
              { label: "Last 6 hours", value: "6h" },
            ]}
          />
        </div>
      </div>

      {stats && (
        <>
          <StatsCards stats={stats} />

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <Card title="Traffic Over Time" subtitle={`Packets per interval (${timeRange})`}>
                <TrafficChart data={stats.trafficOverTime} />
              </Card>
            </div>
            <div>
              <Card title="Protocol Distribution" subtitle="Traffic by protocol">
                <ProtocolPieChart protocols={stats.protocols} />
              </Card>
            </div>
          </div>

          <TopIpsTable ips={stats.topSourceIps} ports={stats.topDestPorts} />

          <RecentAlerts alerts={alerts} />
        </>
      )}

      {!stats && (
        <div className="flex h-64 items-center justify-center text-sm text-zinc-600">
          Loading...
        </div>
      )}
    </div>
  );
}
