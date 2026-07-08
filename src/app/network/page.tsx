"use client";

import { useEffect, useState } from "react";
import { TrafficStats } from "@/lib/types";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { DashboardShell } from "@/components/DashboardShell";

interface SpeedResult {
  latency: number | null;
  download: number | null;
  upload: number | null;
}

export default function NetworkPage() {
  const [ip, setIp] = useState("");
  const [publicIp, setPublicIp] = useState("");
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<SpeedResult>({ latency: null, download: null, upload: null });
  const [stats, setStats] = useState<TrafficStats | null>(null);

  useEffect(() => {
    fetch("/api/network")
      .then((r) => r.json())
      .then((d) => { setIp(d.ip); setPublicIp(d.publicIp || ""); });
  }, []);

  useEffect(() => {
    const es = new EventSource("/api/stream");
    es.addEventListener("stats", (e) => setStats(JSON.parse(e.data)));
    return () => es.close();
  }, []);

  const runTest = async () => {
    setTesting(true);
    setResult({ latency: null, download: null, upload: null });

    const latency = await measureLatency();
    const download = await measureDownload();
    const upload = await measureUpload();

    setResult({ latency, download, upload });
    setTesting(false);
  };

  return (
    <DashboardShell>
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-zinc-100">Network Diagnostics</h1>
        <p className="mt-1 text-sm text-zinc-500">
          Local IP: <span className="font-mono text-zinc-400">{ip || "..."}</span>
          {publicIp && publicIp !== ip && (
            <> &middot; Public: <span className="font-mono text-emerald-400">{publicIp}</span></>
          )}
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <Card title="Speed Test" subtitle="Run to measure bandwidth">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-2 text-sm">
              <span className="text-zinc-500">Latency</span>
              <span className="font-mono text-zinc-100">{result.latency !== null ? `${result.latency} ms` : "—"}</span>
            </div>
            <div className="flex items-center justify-between border-b border-zinc-800 pb-2 text-sm">
              <span className="text-zinc-500">Download</span>
              <span className="font-mono text-zinc-100">{result.download !== null ? `${result.download} Mbps` : "—"}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-zinc-500">Upload</span>
              <span className="font-mono text-zinc-100">{result.upload !== null ? `${result.upload} Mbps` : "—"}</span>
            </div>
            <Button onClick={runTest} disabled={testing} className="w-full">
              {testing ? "Running..." : "Run Speed Test"}
            </Button>
          </div>
        </Card>

        <Card title="Live Traffic" subtitle="Real-time network activity">
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm">
              <StatusDot status={stats ? "active" : "inactive"} />
              <span className="text-zinc-400">{stats ? "Receiving data" : "Connecting..."}</span>
            </div>
            {stats && (
              <>
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2 text-sm">
                  <span className="text-zinc-500">Total Packets</span>
                  <span className="font-mono text-zinc-100">{stats.totalPackets.toLocaleString()}</span>
                </div>
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2 text-sm">
                  <span className="text-zinc-500">Total Alerts</span>
                  <span className="font-mono text-red-400">{stats.totalAlerts}</span>
                </div>
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2 text-sm">
                  <span className="text-zinc-500">Unique IPs</span>
                  <span className="font-mono text-zinc-100">{stats.uniqueIps}</span>
                </div>
                {stats.inspection && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-zinc-500">Packet Rate</span>
                    <span className="font-mono text-zinc-100">{stats.inspection.packetsPerSecond.toFixed(1)}/s</span>
                  </div>
                )}
              </>
            )}
          </div>
        </Card>

        <Card title="Protocols" subtitle="Traffic breakdown">
          <div className="space-y-2">
            {stats ? (
              Object.entries(stats.protocols)
                .sort((a, b) => b[1] - a[1])
                .map(([proto, count]) => (
                  <div key={proto} className="flex items-center justify-between text-sm">
                    <Badge variant="success">{proto}</Badge>
                    <span className="font-mono text-zinc-400">{count}</span>
                  </div>
                ))
            ) : (
              <div className="flex h-20 items-center justify-center text-sm text-zinc-600">Waiting...</div>
            )}
          </div>
        </Card>
      </div>
    </div>
    </DashboardShell>
  );
}

async function measureLatency(): Promise<number> {
  const samples: number[] = [];
  for (let i = 0; i < 5; i++) {
    const t0 = performance.now();
    try {
      await fetch("https://connectivitycheck.gstatic.com/generate_204", {
        mode: "no-cors",
        signal: AbortSignal.timeout(5000),
      });
      samples.push(performance.now() - t0);
    } catch { /* skip */ }
  }
  return samples.length ? Math.round(Math.min(...samples)) : 0;
}

async function measureDownload(): Promise<number> {
  const size = 10_485_760;
  const t0 = performance.now();
  const res = await fetch(`https://speed.cloudflare.com/__down?bytes=${size}`, {
    signal: AbortSignal.timeout(30000),
  });
  if (!res.ok) throw new Error(`Download failed: ${res.status}`);
  const blob = await res.blob();
  const elapsed = performance.now() - t0;
  return parseFloat(((blob.size * 8 / elapsed) / 1000).toFixed(1));
}

async function measureUpload(): Promise<number> {
  const payload = new TextEncoder().encode("x".repeat(1_048_576));
  const streams = 4;
  const t0 = performance.now();
  try {
    const results = await Promise.allSettled(
      Array.from({ length: streams }, () =>
        fetch("https://speed.cloudflare.com/__up", {
          method: "PUT",
          body: payload,
          headers: { "Content-Type": "application/octet-stream" },
          signal: AbortSignal.timeout(30000),
        })
      )
    );
    const succeeded = results.filter((r) => r.status === "fulfilled").length;
    if (succeeded === 0) throw new Error("all upload streams failed");
    const elapsed = performance.now() - t0;
    const totalBits = payload.length * 8 * succeeded;
    return parseFloat(((totalBits / elapsed) / 1000).toFixed(1));
  } catch {
    const res = await fetch("/api/network?type=upload", { method: "POST", body: payload });
    const data = await res.json();
    return data.mbps;
  }
}
