"use client";

import { TrafficStats } from "@/lib/types";
import { useThemeColors } from "@/lib/use-theme-colors";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

const COLORS = [
  "#10b981", "#3b82f6", "#f59e0b", "#ef4444",
  "#8b5cf6", "#ec4899", "#14b8a6", "#f97316",
];

interface ProtocolPieChartProps {
  protocols: TrafficStats["protocols"];
}

export function ProtocolPieChart({ protocols }: ProtocolPieChartProps) {
  const c = useThemeColors();
  const data = Object.entries(protocols)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm" style={{ color: "var(--text-faint)" }}>
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
              background: c.tooltipBg,
              border: `1px solid ${c.tooltipBorder}`,
              borderRadius: "8px",
              fontSize: "12px",
            }}
            itemStyle={{ color: c.tooltipText }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="mt-2 flex flex-wrap justify-center gap-3">
        {data.slice(0, 6).map((entry, index) => (
          <div key={entry.name} className="flex items-center gap-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
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
