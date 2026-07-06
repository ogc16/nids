"use client";

import { useEffect, useState } from "react";
import { TrafficStats, Alert, NetworkAsset } from "@/lib/types";
import { StatsCards } from "@/components/dashboard/StatsCards";
import { TrafficChart } from "@/components/dashboard/TrafficChart";
import { AssetTraffic } from "@/components/dashboard/AssetTraffic";
import { RecentAlerts } from "@/components/dashboard/RecentAlerts";
import { ProtocolPieChart } from "@/components/dashboard/ProtocolPieChart";
import { TopIpsTable } from "@/components/dashboard/TopIpsTable";
import { Card } from "@/components/ui/Card";
import { StatusDot } from "@/components/ui/StatusDot";
import { useAlertSiren } from "@/lib/use-alert-siren";

interface AssetRow {
  asset: NetworkAsset;
  totalPackets: number;
  totalAlerts: number;
  lastSeen: number;
}

export default function Dashboard() {
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const checkAlerts = useAlertSiren();

  useEffect(() => {
    const es = new EventSource("/api/stream");

    es.addEventListener("stats", (e) => {
      setStats(JSON.parse(e.data));
    });

    es.addEventListener("alerts", (e) => {
      const data: Alert[] = JSON.parse(e.data);
      setAlerts(data);
      checkAlerts(data);
    });

    es.addEventListener("assets", (e) => {
      setAssets(JSON.parse(e.data));
    });

    return () => es.close();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-zinc-100">Network Dashboard</h1>
          <p className="mt-1 text-sm text-zinc-500">
            Real-time network traffic monitoring and intrusion detection
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm text-zinc-400">
          <StatusDot status={stats ? "active" : "inactive"} />
          {stats ? "Monitoring" : "Connecting..."}
        </div>
      </div>

      {stats && (
        <>
          <StatsCards stats={stats} />

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <Card title="Traffic Over Time" subtitle="Packets per interval (1m)">
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

          <Card title="Active Assets" subtitle="Traffic volume by asset" action={<a href="/assets" className="text-xs text-emerald-500 hover:text-emerald-400">View all</a>}>
            <AssetTraffic assets={assets} />
          </Card>

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
