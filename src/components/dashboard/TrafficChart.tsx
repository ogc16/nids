"use client";

import { TrafficStats } from "@/lib/types";
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
  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
          <defs>
            <linearGradient id="normalGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="maliciousGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
          <XAxis
            dataKey="time"
            tick={{ fill: "#a1a1aa", fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fill: "#a1a1aa", fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              background: "#18181b",
              border: "1px solid #27272a",
              borderRadius: "8px",
              fontSize: "12px",
            }}
            itemStyle={{ color: "#e4e4e7" }}
            labelStyle={{ color: "#a1a1aa" }}
          />
          <Legend
            wrapperStyle={{ fontSize: "12px", color: "#a1a1aa" }}
          />
          <Area
            type="monotone"
            dataKey="normal"
            stroke="#10b981"
            fill="url(#normalGrad)"
            strokeWidth={2}
            name="Normal Traffic"
            dot={false}
          />
          <Area
            type="monotone"
            dataKey="malicious"
            stroke="#ef4444"
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
