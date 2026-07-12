"use client";

import { useEffect, useState } from "react";
import { TrafficStats } from "@/lib/types";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { DashboardShell } from "@/components/DashboardShell";

interface PingResult {
  min: number | null;
  avg: number | null;
  max: number | null;
  jitter: number | null;
  loss: number | null;
  samples: number[];
}

interface ThroughputResult {
  download: number | null;
  upload: number | null;
  downloadSamples: number[];
  uploadSamples: number[];
}

interface SpeedResult {
  ping: PingResult;
  throughput: ThroughputResult;
  latency: number | null;
  download: number | null;
  upload: number | null;
}

const EMPTY_PING: PingResult = { min: null, avg: null, max: null, jitter: null, loss: null, samples: [] };
const EMPTY_THROUGHPUT: ThroughputResult = { download: null, upload: null, downloadSamples: [], uploadSamples: [] };

export default function NetworkPage() {
  const [ip, setIp] = useState("");
  const [publicIp, setPublicIp] = useState("");
  const [testing, setTesting] = useState(false);
  const [progress, setProgress] = useState("");
  const [result, setResult] = useState<SpeedResult>({
    ping: EMPTY_PING,
    throughput: EMPTY_THROUGHPUT,
    latency: null,
    download: null,
    upload: null,
  });
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
    setProgress("Pinging...");
    setResult({ ping: EMPTY_PING, throughput: EMPTY_THROUGHPUT, latency: null, download: null, upload: null });

    const ping = await measurePing();
    setResult((prev) => ({ ...prev, ping, latency: ping.avg }));

    setProgress("Testing download...");
    const dl = await measureThroughputDownload();
    setResult((prev) => ({
      ...prev,
      throughput: { ...prev.throughput, download: dl.peak, downloadSamples: dl.samples },
      download: dl.peak,
    }));

    setProgress("Testing upload...");
    const ul = await measureThroughputUpload();
    let uploadVal = 0;
    try { uploadVal = ul.peak; } catch { /* ignore */ }
    setResult((prev) => ({
      ...prev,
      throughput: { ...prev.throughput, upload: Number.isFinite(uploadVal) ? uploadVal : 0, uploadSamples: ul.samples },
      upload: Number.isFinite(uploadVal) ? uploadVal : 0,
    }));

    setProgress("");
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
        <Card title="Ping" subtitle="Latency &amp; jitter">
          <div className="space-y-3">
            <PingRow label="Min" value={result.ping.min} unit="ms" />
            <PingRow label="Avg" value={result.ping.avg} unit="ms" highlight />
            <PingRow label="Max" value={result.ping.max} unit="ms" />
            <PingRow label="Jitter" value={result.ping.jitter} unit="ms" />
            <PingRow label="Loss" value={result.ping.loss} unit="%" />
            {result.ping.samples.length > 0 && (
              <div className="pt-2 border-t border-zinc-800">
                <div className="text-[10px] text-zinc-600 mb-1">Samples ({result.ping.samples.length})</div>
                <div className="flex flex-wrap gap-1">
                  {result.ping.samples.map((s, i) => (
                    <span key={i} className="inline-block px-1.5 py-0.5 rounded bg-zinc-800 text-[10px] font-mono text-zinc-400">
                      {s.toFixed(1)}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>

        <Card title="Throughput" subtitle="Sustained transfer rate">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-2 text-sm">
              <span className="text-zinc-500">Download</span>
              <span className="font-mono text-zinc-100">
                {result.throughput.download !== null ? `${result.throughput.download} Mbps` : "—"}
              </span>
            </div>
            <div className="flex items-center justify-between border-b border-zinc-800 pb-2 text-sm">
              <span className="text-zinc-500">Upload</span>
              <span className="font-mono text-zinc-100">
                {result.throughput.upload !== null ? `${result.throughput.upload} Mbps` : "—"}
              </span>
            </div>
            {result.throughput.downloadSamples.length > 0 && (
              <div className="pt-1">
                <div className="text-[10px] text-zinc-600 mb-1">Download Samples</div>
                <MiniBarChart values={result.throughput.downloadSamples} color="#58a6ff" />
              </div>
            )}
            {result.throughput.uploadSamples.length > 0 && (
              <div>
                <div className="text-[10px] text-zinc-600 mb-1">Upload Samples</div>
                <MiniBarChart values={result.throughput.uploadSamples} color="#3fb950" />
              </div>
            )}
          </div>
        </Card>

        <Card title="Speed Test" subtitle="Run to measure bandwidth">
          <div className="space-y-3">
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
            {progress && <div className="text-xs text-zinc-500 text-center">{progress}</div>}
            <Button onClick={runTest} disabled={testing} className="w-full">
              {testing ? "Running..." : "Run Speed Test"}
            </Button>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
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

function PingRow({ label, value, unit, highlight }: { label: string; value: number | null; unit: string; highlight?: boolean }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className={highlight ? "text-zinc-300 font-medium" : "text-zinc-500"}>{label}</span>
      <span className={`font-mono ${highlight ? "text-zinc-100 font-semibold" : "text-zinc-100"}`}>
        {value !== null ? `${value.toFixed(1)} ${unit}` : "—"}
      </span>
    </div>
  );
}

function MiniBarChart({ values, color }: { values: number[]; color: string }) {
  if (values.length === 0) return null;
  const max = Math.max(...values, 1);
  return (
    <div className="flex items-end gap-px h-8">
      {values.map((v, i) => (
        <div
          key={i}
          className="flex-1 rounded-t-sm min-w-[3px]"
          style={{
            height: `${Math.max(4, (v / max) * 100)}%`,
            background: color,
            opacity: 0.4 + (v / max) * 0.6,
          }}
          title={`${v.toFixed(1)} Mbps`}
        />
      ))}
    </div>
  );
}

async function measurePing(): Promise<PingResult> {
  const PING_COUNT = 20;
  const samples: number[] = [];
  let losses = 0;

  const controller = new AbortController();
  const timeout = AbortSignal.timeout(2000);

  for (let i = 0; i < PING_COUNT; i++) {
    const t0 = performance.now();
    try {
      const res = await fetch("https://speed.cloudflare.com/__down?bytes=0", {
        cache: "no-store",
        keepalive: true,
        signal: timeout,
      });
      if (res.ok) {
        samples.push(performance.now() - t0);
      } else {
        losses++;
      }
    } catch {
      losses++;
    }
  }

  if (samples.length === 0) {
    return { min: 0, avg: 0, max: 0, jitter: 0, loss: 100, samples: [] };
  }

  const sorted = [...samples].sort((a, b) => a - b);
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const avg = samples.reduce((a, b) => a + b, 0) / samples.length;

  let jitterSum = 0;
  for (let i = 1; i < samples.length; i++) {
    jitterSum += Math.abs(samples[i] - samples[i - 1]);
  }
  const jitter = jitterSum / Math.max(1, samples.length - 1);
  const loss = Math.round((losses / PING_COUNT) * 100);

  return {
    min: Math.round(min * 10) / 10,
    avg: Math.round(avg * 10) / 10,
    max: Math.round(max * 10) / 10,
    jitter: Math.round(jitter * 10) / 10,
    loss,
    samples: samples.map((s) => Math.round(s * 10) / 10),
  };
}

async function measureThroughputDownload(): Promise<{ peak: number; samples: number[] }> {
  const SAMPLES = 6;
  const SIZE = 10_485_760;
  const samples: number[] = [];

  for (let i = 0; i < SAMPLES; i++) {
    const t0 = performance.now();
    try {
      const res = await fetch(`https://speed.cloudflare.com/__down?bytes=${SIZE}`, {
        signal: AbortSignal.timeout(15000),
      });
      if (!res.ok) continue;
      const blob = await res.blob();
      const elapsed = performance.now() - t0;
      if (elapsed > 0) {
        samples.push(parseFloat(((blob.size * 8 / elapsed) / 1000).toFixed(1)));
      }
    } catch {
      /* skip failed sample */
    }
  }

  const peak = samples.length > 0 ? Math.max(...samples) : 0;
  return { peak, samples };
}

async function measureThroughputUpload(): Promise<{ peak: number; samples: number[] }> {
  const SAMPLES = 6;
  const SIZE = 1_048_576;
  const payload = new TextEncoder().encode("x".repeat(SIZE));
  const samples: number[] = [];

  for (let i = 0; i < SAMPLES; i++) {
    try {
      const t0 = performance.now();
      const res = await fetch("https://speed.cloudflare.com/__up", {
        method: "POST",
        body: payload,
        signal: AbortSignal.timeout(15000),
      });
      const elapsed = performance.now() - t0;
      if (res.ok && elapsed > 0) {
        samples.push(parseFloat(((SIZE * 8 / elapsed) / 1000).toFixed(1)));
      }
    } catch {
      /* skip failed sample */
    }
  }

  if (samples.length === 0) {
    try {
      const t0 = performance.now();
      const res = await fetch("/api/network?type=upload", {
        method: "POST",
        body: payload,
        credentials: "include",
        signal: AbortSignal.timeout(15000),
      });
      if (res.ok) {
        const data = await res.json();
        if (typeof data.mbps === "number" && data.mbps > 0) {
          samples.push(data.mbps);
        }
      }
    } catch {
      /* fallback failed */
    }
  }

  const peak = samples.length > 0 ? Math.max(...samples) : 0;
  return { peak, samples };
}
