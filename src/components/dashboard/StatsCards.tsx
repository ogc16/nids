import { TrafficStats } from "@/lib/types";
import { StatusDot } from "@/components/ui/StatusDot";

interface StatsCardsProps {
  stats: TrafficStats;
}

export function StatsCards({ stats }: StatsCardsProps) {
  const cards = [
    {
      label: "Total Packets",
      value: stats.totalPackets.toLocaleString(),
      status: "active" as const,
      sub: "In current time range",
    },
    {
      label: "Alerts Generated",
      value: stats.totalAlerts.toLocaleString(),
      status: stats.totalAlerts > 50 ? "error" as const : stats.totalAlerts > 10 ? "warning" as const : "active" as const,
      sub: `${((stats.totalAlerts / Math.max(stats.totalPackets, 1)) * 100).toFixed(2)}% of traffic`,
    },
    {
      label: "Unique IPs",
      value: stats.uniqueIps.toLocaleString(),
      status: "active" as const,
      sub: "Sources & destinations",
    },
    {
      label: "Protocols",
      value: Object.keys(stats.protocols).length.toString(),
      status: "active" as const,
      sub: Object.entries(stats.protocols)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 3)
        .map(([p]) => p)
        .join(", "),
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {cards.map((card) => (
        <div
          key={card.label}
          className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 backdrop-blur-sm"
        >
          <div className="flex items-center gap-2">
            <StatusDot status={card.status} />
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-500">
              {card.label}
            </span>
          </div>
          <div className="mt-2 text-2xl font-bold text-zinc-100">{card.value}</div>
          <div className="mt-0.5 text-xs text-zinc-600">{card.sub}</div>
        </div>
      ))}
    </div>
  );
}
