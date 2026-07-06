"use client";

import { useEffect, useState } from "react";
import { NetworkAsset } from "@/lib/types";
import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";
import { StatusDot } from "@/components/ui/StatusDot";

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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-zinc-100">Network Assets</h1>
          <p className="mt-1 text-sm text-zinc-500">
            {assets.length} assets tracked
          </p>
        </div>
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value.toLowerCase())}
          placeholder="Filter by name, IP, group..."
          className="w-64 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-emerald-500"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {filtered.map((row) => (
          <div
            key={row.asset.id}
            className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 backdrop-blur-sm"
          >
            <div className="flex items-start justify-between">
              <div className="min-w-0 flex-1">
                {editingId === row.asset.id ? (
                  <div className="space-y-2">
                    <input
                      value={editForm.nickname}
                      onChange={(e) => setEditForm((f) => ({ ...f, nickname: e.target.value }))}
                      className="w-full rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-sm text-zinc-100 outline-none focus:border-emerald-500"
                      placeholder="Nickname (optional)"
                      autoFocus
                    />
                    <div className="flex gap-2">
                      <select
                        value={editForm.type}
                        onChange={(e) => setEditForm((f) => ({ ...f, type: e.target.value }))}
                        className="rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-100 outline-none focus:border-emerald-500"
                      >
                        {["server", "workstation", "database", "firewall", "router", "service", "other"].map((t) => (
                          <option key={t} value={t}>{t}</option>
                        ))}
                      </select>
                      <input
                        value={editForm.group}
                        onChange={(e) => setEditForm((f) => ({ ...f, group: e.target.value }))}
                        className="rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-100 outline-none focus:border-emerald-500"
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
                        className="rounded bg-zinc-700 px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-600"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => startEdit(row)}
                      className="text-sm font-semibold text-zinc-100 hover:text-emerald-400 transition-colors text-left"
                    >
                      {row.asset.name}
                    </button>
                    {row.asset.nickname && (
                      <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400">
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
                <p className="mt-0.5 font-mono text-xs text-zinc-500">
                  {row.asset.ip}
                </p>
                <p className="mt-0.5 text-xs text-zinc-600">
                  {row.asset.group}
                  {row.asset.tags.length > 0 && (
                    <span className="ml-2">
                      {row.asset.tags.map((t) => (
                        <span
                          key={t}
                          className="ml-1 rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400"
                        >
                          {t}
                        </span>
                      ))}
                    </span>
                  )}
                </p>
                {row.asset.description && (
                  <p className="mt-1 text-xs text-zinc-600">{row.asset.description}</p>
                )}
              </div>
            </div>

            <div className="mt-3 grid grid-cols-4 gap-3 border-t border-zinc-800 pt-3 text-center text-xs">
              <div>
                <div className="text-zinc-400">{row.totalPackets}</div>
                <div className="text-zinc-600">packets</div>
              </div>
              <div>
                <div className="text-zinc-400">
                  {row.incomingPackets} &rarr; {row.outgoingPackets}
                </div>
                <div className="text-zinc-600">in / out</div>
              </div>
              <div>
                <div className="text-zinc-400">{formatBytes(row.bytesIn + row.bytesOut)}</div>
                <div className="text-zinc-600">volume</div>
              </div>
              <div>
                <div className={row.totalAlerts > 0 ? "text-red-400" : "text-zinc-400"}>
                  {row.totalAlerts}
                </div>
                <div className="text-zinc-600">alerts</div>
              </div>
            </div>

            {row.lastSeen > 0 && (
              <div className="mt-2 flex items-center gap-1.5 text-[10px] text-zinc-600">
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
          <div className="flex h-48 items-center justify-center text-sm text-zinc-600">
            No assets match filter.
          </div>
        </Card>
      )}
    </div>
  );
}
