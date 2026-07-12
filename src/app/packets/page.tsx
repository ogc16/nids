"use client";

import { useEffect, useState } from "react";
import { Packet } from "@/lib/types";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { downloadAsJson, downloadAsCsv } from "@/lib/export";
import { DashboardShell } from "@/components/DashboardShell";

export default function PacketsPage() {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [filter, setFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    const es = new EventSource("/api/stream");

    es.addEventListener("packets", (e) => {
      setPackets(JSON.parse(e.data));
    });

    return () => es.close();
  }, []);

  const filtered = packets.filter((p) => {
    if (filter === "malicious" && !p.isMalicious) return false;
    if (filter === "normal" && p.isMalicious) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        p.srcIp.includes(q) ||
        p.dstIp.includes(q) ||
        p.protocol.toLowerCase().includes(q) ||
        p.payload.toLowerCase().includes(q) ||
        p.id.includes(q)
      );
    }
    return true;
  });

  return (
    <DashboardShell>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold" style={{ color: "var(--text-primary)" }}>Packet Capture</h1>
            <p className="mt-1 text-sm" style={{ color: "var(--text-muted)" }}>
              Live packet stream - {packets.length} captured, {filtered.length} shown
            </p>
          </div>
          <div className="flex items-center gap-3">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IP, protocol, payload..."
              className="w-64 rounded-lg border px-3 py-1.5 text-sm outline-none focus:border-emerald-500"
              style={{ borderColor: "var(--border-strong)", backgroundColor: "var(--bg-input)", color: "var(--text-primary)" }}
            />
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="rounded-lg border px-3 py-1.5 text-sm outline-none focus:border-emerald-500"
              style={{ borderColor: "var(--border-strong)", backgroundColor: "var(--bg-input)", color: "var(--text-primary)" }}
            >
              <option value="all">All Packets</option>
              <option value="malicious">Malicious Only</option>
              <option value="normal">Normal Only</option>
            </select>
            <Button variant="secondary" size="sm" onClick={() => downloadAsJson(packets, "packets")}>
              Export JSON
            </Button>
            <Button variant="secondary" size="sm" onClick={() => downloadAsCsv(packets as unknown as Record<string, unknown>[], "packets")}>
              Export CSV
            </Button>
          </div>
        </div>

        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b text-xs uppercase tracking-wider" style={{ borderColor: "var(--border-default)", color: "var(--text-muted)" }}>
                  <th className="pb-3 pr-4 font-medium">Time</th>
                  <th className="pb-3 pr-4 font-medium">Protocol</th>
                  <th className="pb-3 pr-4 font-medium">Source</th>
                  <th className="pb-3 pr-4 font-medium">Destination</th>
                  <th className="pb-3 pr-4 font-medium">Length</th>
                  <th className="pb-3 pr-4 font-medium">Flags</th>
                  <th className="pb-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 200).map((pkt) => (
                  <tr
                    key={pkt.id}
                    className="border-b transition-colors"
                    style={{
                      borderColor: "var(--border-default)",
                      backgroundColor: pkt.isMalicious ? "rgba(239, 68, 68, 0.05)" : "transparent",
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "var(--bg-hover)"; }}
                    onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = pkt.isMalicious ? "rgba(239, 68, 68, 0.05)" : "transparent"; }}
                  >
                    <td className="py-2.5 pr-4 font-mono text-xs" style={{ color: "var(--text-muted)" }}>
                      {new Date(pkt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 pr-4">
                      <span className="rounded px-2 py-0.5 text-xs font-medium" style={{ backgroundColor: "var(--bg-muted)", color: "var(--text-secondary)" }}>
                        {pkt.protocol}
                      </span>
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-xs" style={{ color: "var(--text-secondary)" }}>
                      {pkt.srcIp}:{pkt.srcPort}
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-xs" style={{ color: "var(--text-secondary)" }}>
                      {pkt.dstIp}:{pkt.dstPort}
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-xs" style={{ color: "var(--text-muted)" }}>
                      {pkt.length} B
                    </td>
                    <td className="py-2.5 pr-4">
                      <div className="flex gap-1">
                        {pkt.flags.map((f) => (
                          <span
                            key={f}
                            className="rounded px-1.5 py-0.5 text-[10px] font-medium"
                            style={{ backgroundColor: "var(--bg-muted)", color: "var(--text-muted)" }}
                          >
                            {f}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-2.5">
                      {pkt.isMalicious ? (
                        <Badge variant="error">Malicious</Badge>
                      ) : (
                        <Badge variant="success">Normal</Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </DashboardShell>
  );
}
