import { TrafficStats } from "@/lib/types";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

const COLORS = [
  "#10b981", "#3b82f6", "#f59e0b", "#ef4444",
  "#8b5cf6", "#ec4899", "#14b8a6", "#f97316",
];

interface ProtocolPieChartProps {
  protocols: TrafficStats["protocols"];
}

export function ProtocolPieChart({ protocols }: ProtocolPieChartProps) {
  const data = Object.entries(protocols)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-zinc-600">
        No data
      </div>
    );
  }

  return (
    <div className="h-48 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={45}
            outerRadius={70}
            paddingAngle={2}
            dataKey="value"
          >
            {data.map((_, index) => (
              <Cell
                key={`cell-${index}`}
                fill={COLORS[index % COLORS.length]}
                className="outline-none"
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "#18181b",
              border: "1px solid #27272a",
              borderRadius: "8px",
              fontSize: "12px",
            }}
            itemStyle={{ color: "#e4e4e7" }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="mt-2 flex flex-wrap justify-center gap-3">
        {data.slice(0, 6).map((entry, index) => (
          <div key={entry.name} className="flex items-center gap-1.5 text-xs text-zinc-400">
            <span
              className="inline-block h-2.5 w-2.5 rounded-full"
              style={{ backgroundColor: COLORS[index % COLORS.length] }}
            />
            {entry.name}
          </div>
        ))}
      </div>
    </div>
  );
}
