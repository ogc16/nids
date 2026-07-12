"use client";

import { TrafficStats } from "@/lib/types";
import { useThemeColors } from "@/lib/use-theme-colors";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

interface TrafficChartProps {
  data: TrafficStats["trafficOverTime"];
}

export function TrafficChart({ data }: TrafficChartProps) {
  const c = useThemeColors();

  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
          <defs>
            <linearGradient id="normalGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={c.normalGradStart} stopOpacity={0.3} />
              <stop offset="95%" stopColor={c.normalGradEnd} stopOpacity={0} />
            </linearGradient>
            <linearGradient id="maliciousGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={c.maliciousGradStart} stopOpacity={0.3} />
              <stop offset="95%" stopColor={c.maliciousGradEnd} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={c.grid} />
          <XAxis
            dataKey="time"
            tick={{ fill: c.tick, fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fill: c.tick, fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              background: c.tooltipBg,
              border: `1px solid ${c.tooltipBorder}`,
              borderRadius: "8px",
              fontSize: "12px",
            }}
            itemStyle={{ color: c.tooltipText }}
            labelStyle={{ color: c.tooltipLabel }}
          />
          <Legend
            wrapperStyle={{ fontSize: "12px", color: c.tick }}
          />
          <Area
            type="monotone"
            dataKey="normal"
            stroke={c.normalStroke}
            fill="url(#normalGrad)"
            strokeWidth={2}
            name="Normal Traffic"
            dot={false}
          />
          <Area
            type="monotone"
            dataKey="malicious"
            stroke={c.maliciousStroke}
            fill="url(#maliciousGrad)"
            strokeWidth={2}
            name="Malicious Traffic"
            dot={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
