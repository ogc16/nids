"use client";

import { useEffect, useState } from "react";
import { NetworkAsset } from "@/lib/types";
import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";
import { StatusDot } from "@/components/ui/StatusDot";
import { DashboardShell } from "@/components/DashboardShell";

const typeBadge: Record<string, "info" | "error" | "success" | "warning"> = {
  server: "info",
  database: "error",
  firewall: "error",
  router: "success",
  workstation: "warning",
  service: "success",
  other: "info",
};

const criticalityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

interface AssetRow {
  asset: NetworkAsset;
  totalPackets: number;
  incomingPackets: number;
  outgoingPackets: number;
  totalAlerts: number;
  bytesIn: number;
  bytesOut: number;
  lastSeen: number;
}

export default function AssetsPage() {
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [filter, setFilter] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState({ nickname: "", type: "", group: "" });

  useEffect(() => {
    const es = new EventSource("/api/stream");

    es.addEventListener("assets", (e) => {
      const data = JSON.parse(e.data);
      setAssets(
        data.sort(
          (a: AssetRow, b: AssetRow) =>
            (criticalityOrder[a.asset.criticality] ?? 99) -
            (criticalityOrder[b.asset.criticality] ?? 99)
        )
      );
    });

    return () => es.close();
  }, []);

  const startEdit = (row: AssetRow) => {
    setEditingId(row.asset.id);
    setEditForm({ nickname: row.asset.nickname, type: row.asset.type, group: row.asset.group });
  };

  const saveEdit = async (id: string) => {
    await fetch("/api/assets", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, nickname: editForm.nickname, type: editForm.type, group: editForm.group }),
    });
    setEditingId(null);
  };

  const cancelEdit = () => setEditingId(null);

  const filtered = filter
    ? assets.filter(
        (r) =>
          r.asset.name.toLowerCase().includes(filter) ||
          r.asset.nickname.toLowerCase().includes(filter) ||
          r.asset.ip.includes(filter) ||
          r.asset.group.toLowerCase().includes(filter) ||
          r.asset.type.includes(filter)
      )
    : assets;

  const formatBytes = (b: number) => {
    if (b > 1_000_000) return (b / 1_000_000).toFixed(1) + " MB";
    if (b > 1_000) return (b / 1_000).toFixed(1) + " KB";
    return b + " B";
  };

  const inputStyle: React.CSSProperties = { borderColor: "var(--border-strong)", backgroundColor: "var(--bg-input)", color: "var(--text-primary)" };

  return (
    <DashboardShell>
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold" style={{ color: "var(--text-primary)" }}>Network Assets</h1>
          <p className="mt-1 text-sm" style={{ color: "var(--text-muted)" }}>
            {assets.length} assets tracked
          </p>
        </div>
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value.toLowerCase())}
          placeholder="Filter by name, IP, group..."
          className="w-64 rounded-lg border px-3 py-1.5 text-sm outline-none focus:border-emerald-500"
          style={inputStyle}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {filtered.map((row) => (
          <div
            key={row.asset.id}
            className="rounded-xl border backdrop-blur-sm p-4"
            style={{ borderColor: "var(--border-default)", backgroundColor: "var(--bg-surface)", boxShadow: "var(--shadow-sm)" }}
          >
            <div className="flex items-start justify-between">
              <div className="min-w-0 flex-1">
                {editingId === row.asset.id ? (
                  <div className="space-y-2">
                    <input
                      value={editForm.nickname}
                      onChange={(e) => setEditForm((f) => ({ ...f, nickname: e.target.value }))}
                      className="w-full rounded border px-2 py-1 text-sm outline-none focus:border-emerald-500"
                      style={inputStyle}
                      placeholder="Nickname (optional)"
                      autoFocus
                    />
                    <div className="flex gap-2">
                      <select
                        value={editForm.type}
                        onChange={(e) => setEditForm((f) => ({ ...f, type: e.target.value }))}
                        className="rounded border px-2 py-1 text-xs outline-none focus:border-emerald-500"
                        style={inputStyle}
                      >
                        {["server", "workstation", "database", "firewall", "router", "service", "other"].map((t) => (
                          <option key={t} value={t}>{t}</option>
                        ))}
                      </select>
                      <input
                        value={editForm.group}
                        onChange={(e) => setEditForm((f) => ({ ...f, group: e.target.value }))}
                        className="rounded border px-2 py-1 text-xs outline-none focus:border-emerald-500"
                        style={inputStyle}
                        placeholder="Group"
                      />
                      <button
                        onClick={() => saveEdit(row.asset.id)}
                        className="rounded bg-emerald-600 px-2 py-1 text-xs font-medium text-white hover:bg-emerald-500"
                      >
                        Save
                      </button>
                      <button
                        onClick={cancelEdit}
                        className="rounded px-2 py-1 text-xs transition-colors"
                        style={{ backgroundColor: "var(--bg-muted)", color: "var(--text-secondary)" }}
                        onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "var(--bg-hover)"; }}
                        onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "var(--bg-muted)"; }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => startEdit(row)}
                      className="text-sm font-semibold transition-colors text-left hover:text-emerald-500"
                      style={{ color: "var(--text-primary)" }}
                    >
                      {row.asset.name}
                    </button>
                    {row.asset.nickname && (
                      <span className="rounded px-1.5 py-0.5 text-[10px]" style={{ backgroundColor: "var(--bg-muted)", color: "var(--text-muted)" }}>
                        {row.asset.nickname}
                      </span>
                    )}
                    <Badge variant={typeBadge[row.asset.type] ?? "info"}>
                      {row.asset.type}
                    </Badge>
                    <Badge variant={row.asset.criticality}>
                      {row.asset.criticality}
                    </Badge>
                  </div>
                )}
                <p className="mt-0.5 font-mono text-xs" style={{ color: "var(--text-muted)" }}>
                  {row.asset.ip}
                </p>
                <p className="mt-0.5 text-xs" style={{ color: "var(--text-faint)" }}>
                  {row.asset.group}
                  {row.asset.tags.length > 0 && (
                    <span className="ml-2">
                      {row.asset.tags.map((t) => (
                        <span
                          key={t}
                          className="ml-1 rounded px-1.5 py-0.5 text-[10px]"
                          style={{ backgroundColor: "var(--bg-muted)", color: "var(--text-muted)" }}
                        >
                          {t}
                        </span>
                      ))}
                    </span>
                  )}
                </p>
                {row.asset.description && (
                  <p className="mt-1 text-xs" style={{ color: "var(--text-faint)" }}>{row.asset.description}</p>
                )}
              </div>
            </div>

            <div className="mt-3 grid grid-cols-4 gap-3 border-t pt-3 text-center text-xs" style={{ borderColor: "var(--border-default)" }}>
              <div>
                <div style={{ color: "var(--text-muted)" }}>{row.totalPackets}</div>
                <div style={{ color: "var(--text-faint)" }}>packets</div>
              </div>
              <div>
                <div style={{ color: "var(--text-muted)" }}>
                  {row.incomingPackets} &rarr; {row.outgoingPackets}
                </div>
                <div style={{ color: "var(--text-faint)" }}>in / out</div>
              </div>
              <div>
                <div style={{ color: "var(--text-muted)" }}>{formatBytes(row.bytesIn + row.bytesOut)}</div>
                <div style={{ color: "var(--text-faint)" }}>volume</div>
              </div>
              <div>
                <div className={row.totalAlerts > 0 ? "text-red-500" : ""} style={row.totalAlerts === 0 ? { color: "var(--text-muted)" } : undefined}>
                  {row.totalAlerts}
                </div>
                <div style={{ color: "var(--text-faint)" }}>alerts</div>
              </div>
            </div>

            {row.lastSeen > 0 && (
              <div className="mt-2 flex items-center gap-1.5 text-[10px]" style={{ color: "var(--text-faint)" }}>
                <StatusDot
                  status={Date.now() - row.lastSeen < 10000 ? "active" : "inactive"}
                />
                {Date.now() - row.lastSeen < 10000
                  ? "Active now"
                  : `Last seen ${new Date(row.lastSeen).toLocaleTimeString()}`}
              </div>
            )}
          </div>
        ))}
      </div>

      {filtered.length === 0 && (
        <Card>
          <div className="flex h-48 items-center justify-center text-sm" style={{ color: "var(--text-faint)" }}>
            No assets match filter.
          </div>
        </Card>
      )}
    </div>
    </DashboardShell>
  );
}
