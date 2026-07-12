"use client";

import { useEffect, useState } from "react";
import { TrafficStats } from "@/lib/types";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { DashboardShell } from "@/components/DashboardShell";
import { useThemeColors } from "@/lib/use-theme-colors";

interface PingResult {
  min: number | null;
  avg: number | null;
  median: number | null;
  max: number | null;
  jitter: number | null;
  loss: number | null;
  samples: number[];
  dnsTime: number | null;
  connectTime: number | null;
}

interface ThroughputResult {
  download: number | null;
  upload: number | null;
  downloadSamples: number[];
  uploadSamples: number[];
  downloadTtfb: number | null;
  uploadTtfb: number | null;
  downloadConnections: number[];
  uploadConnections: number[];
}

interface SpeedResult {
  ping: PingResult;
  throughput: ThroughputResult;
  latency: number | null;
  download: number | null;
  upload: number | null;
}

const EMPTY_PING: PingResult = { min: null, avg: null, median: null, max: null, jitter: null, loss: null, samples: [], dnsTime: null, connectTime: null };
const EMPTY_THROUGHPUT: ThroughputResult = { download: null, upload: null, downloadSamples: [], uploadSamples: [], downloadTtfb: null, uploadTtfb: null, downloadConnections: [], uploadConnections: [] };

function median(sorted: number[]): number {
  if (sorted.length === 0) return 0;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function trimmedMean(samples: number[], trimPct = 0.1): number {
  if (samples.length === 0) return 0;
  const sorted = [...samples].sort((a, b) => a - b);
  const trimCount = Math.floor(samples.length * trimPct);
  const trimmed = sorted.slice(trimCount, sorted.length - trimCount);
  return trimmed.length > 0 ? trimmed.reduce((a, b) => a + b, 0) / trimmed.length : 0;
}

type TestPhase = "idle" | "ping" | "download" | "upload";

export default function NetworkPage() {
  const c = useThemeColors();
  const [ip, setIp] = useState("");
  const [publicIp, setPublicIp] = useState("");
  const [testing, setTesting] = useState(false);
  const [phase, setPhase] = useState<TestPhase>("idle");
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
    setPhase("ping");
    setResult({ ping: EMPTY_PING, throughput: EMPTY_THROUGHPUT, latency: null, download: null, upload: null });

    const ping = await measurePing();
    setResult((prev) => ({ ...prev, ping, latency: ping.median ?? ping.avg }));

    setPhase("download");
    const dl = await measureThroughputDownload();
    setResult((prev) => ({
      ...prev,
      throughput: {
        ...prev.throughput,
        download: dl.trimmedMean,
        downloadSamples: dl.samples,
        downloadTtfb: dl.ttfb,
        downloadConnections: dl.connectionTimes,
      },
      download: dl.trimmedMean,
    }));

    setPhase("upload");
    const ul = await measureThroughputUpload();
    let uploadVal = 0;
    try { uploadVal = ul.trimmedMean; } catch { /* ignore */ }
    setResult((prev) => ({
      ...prev,
      throughput: {
        ...prev.throughput,
        upload: Number.isFinite(uploadVal) ? uploadVal : 0,
        uploadSamples: ul.samples,
        uploadTtfb: ul.ttfb,
        uploadConnections: ul.connectionTimes,
      },
      upload: Number.isFinite(uploadVal) ? uploadVal : 0,
    }));

    setPhase("idle");
    setTesting(false);
  };

  const connectionQuality = (latency: number | null, jitter: number | null): { label: string; color: string } => {
    if (latency === null) return { label: "—", color: "text-zinc-500" };
    const score = latency + (jitter ?? 0) * 2;
    if (score < 30) return { label: "Excellent", color: "text-emerald-500" };
    if (score < 60) return { label: "Good", color: "text-blue-500" };
    if (score < 120) return { label: "Fair", color: "text-yellow-500" };
    return { label: "Poor", color: "text-red-500" };
  };

  const quality = connectionQuality(result.ping.median ?? result.ping.avg, result.ping.jitter);

  const pingDone = phase === "idle" || phase === "download" || phase === "upload";
  const dlDone = phase === "idle" || phase === "upload";

  return (
    <DashboardShell>
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold" style={{ color: "var(--text-primary)" }}>Network Diagnostics</h1>
        <p className="mt-1 text-sm" style={{ color: "var(--text-muted)" }}>
          Local IP: <span className="font-mono" style={{ color: "var(--text-muted)" }}>{ip || "..."}</span>
          {publicIp && publicIp !== ip && (
            <> &middot; Public: <span className="font-mono text-emerald-500">{publicIp}</span></>
          )}
          {result.ping.median !== null && (
            <> &middot; Quality: <span className={`font-semibold ${quality.color}`}>{quality.label}</span></>
          )}
        </p>
      </div>

      {testing && (
        <div className="fixed inset-0 z-50 flex flex-col items-center justify-center backdrop-blur-sm" style={{ backgroundColor: "var(--bg-body)", opacity: 0.85 }}>
          <span className="loader-wifi text-zinc-800" style={{ "--loader-wifi-size": "1.5px" } as React.CSSProperties} />
          <p className="mt-4 text-sm font-medium" style={{ color: "var(--text-muted)" }}>
            {phase === "ping" ? "Measuring latency..." : phase === "download" ? "Testing download speed..." : "Testing upload speed..."}
          </p>
          <div className="mt-3 flex items-center gap-1.5">
            {(["ping", "download", "upload"] as const).map((p) => {
              const active = phase === p;
              const done = (p === "ping" && pingDone) || (p === "download" && dlDone) || (p === "upload" && phase === "idle");
              return (
                <div key={p} className="flex items-center gap-1.5">
                  <div
                    className={`flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                      active ? "bg-blue-500/15 text-blue-500" : ""
                    }`}
                    style={!active ? { backgroundColor: done ? "var(--bg-muted)" : "transparent", color: done ? "var(--text-muted)" : "var(--text-faint)" } : undefined}
                  >
                    {done && !active && (
                      <svg className="h-2.5 w-2.5 text-emerald-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    )}
                    {p === "ping" ? "Ping" : p === "download" ? "Download" : "Upload"}
                  </div>
                  {p !== "upload" && (
                    <svg className="h-2.5 w-2.5" style={{ color: done ? "var(--text-faint)" : "var(--border-strong)" }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                    </svg>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <Card title="Ping" subtitle="Latency &amp; jitter">
          <div className="space-y-3">
            {phase === "ping" ? (
              <SkeletonRows rows={6} />
            ) : (
              <>
                <PingRow label="Min" value={result.ping.min} unit="ms" />
                <PingRow label="Median" value={result.ping.median} unit="ms" highlight />
                <PingRow label="Avg" value={result.ping.avg} unit="ms" />
                <PingRow label="Max" value={result.ping.max} unit="ms" />
                <PingRow label="Jitter" value={result.ping.jitter} unit="ms" />
                <PingRow label="Loss" value={result.ping.loss} unit="%" />
              </>
            )}
            {result.ping.samples.length > 0 && (
              <div className="pt-2 border-t" style={{ borderColor: "var(--border-default)" }}>
                <div className="text-[10px] mb-1" style={{ color: "var(--text-faint)" }}>Samples ({result.ping.samples.length})</div>
                <div className="flex flex-wrap gap-1">
                  {result.ping.samples.map((s, i) => (
                    <span key={i} className="inline-block px-1.5 py-0.5 rounded font-mono text-[10px]" style={{ backgroundColor: "var(--bg-muted)", color: "var(--text-muted)" }}>
                      {s.toFixed(1)}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>

        <Card title="Connection" subtitle="DNS &amp; handshake timing">
          <div className="space-y-3">
            {phase === "ping" ? (
              <SkeletonRows rows={4} />
            ) : (
              <>
                <PingRow label="DNS Lookup" value={result.ping.dnsTime} unit="ms" />
                <PingRow label="TCP Connect" value={result.ping.connectTime} unit="ms" />
                <PingRow label="Download TTFB" value={result.throughput.downloadTtfb} unit="ms" />
                <PingRow label="Upload TTFB" value={result.throughput.uploadTtfb} unit="ms" />
              </>
            )}
            {result.throughput.downloadConnections.length > 0 && (
              <div className="pt-2 border-t" style={{ borderColor: "var(--border-default)" }}>
                <div className="text-[10px] mb-1" style={{ color: "var(--text-faint)" }}>Download Conn. Times</div>
                <div className="flex flex-wrap gap-1">
                  {result.throughput.downloadConnections.map((t, i) => (
                    <span key={i} className="inline-block px-1.5 py-0.5 rounded font-mono text-[10px] text-blue-500" style={{ backgroundColor: "var(--bg-muted)" }}>
                      {t.toFixed(0)}ms
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>

        <Card title="Throughput" subtitle="Median transfer rate">
          <div className="space-y-3">
            {phase === "download" || phase === "upload" ? (
              <SkeletonRows rows={2} />
            ) : (
              <>
                <div className="flex items-center justify-between border-b pb-2 text-sm" style={{ borderColor: "var(--border-default)" }}>
                  <span style={{ color: "var(--text-muted)" }}>Download</span>
                  <span className="font-mono" style={{ color: "var(--text-primary)" }}>
                    {result.throughput.download !== null ? `${result.throughput.download} Mbps` : "—"}
                  </span>
                </div>
                <div className="flex items-center justify-between border-b pb-2 text-sm" style={{ borderColor: "var(--border-default)" }}>
                  <span style={{ color: "var(--text-muted)" }}>Upload</span>
                  <span className="font-mono" style={{ color: "var(--text-primary)" }}>
                    {result.throughput.upload !== null ? `${result.throughput.upload} Mbps` : "—"}
                  </span>
                </div>
              </>
            )}
            {result.throughput.downloadSamples.length > 0 && (
              <div className="pt-1">
                <div className="text-[10px] mb-1" style={{ color: "var(--text-faint)" }}>Download Samples</div>
                <MiniBarChart values={result.throughput.downloadSamples} color={c.barBlue} active={phase === "download"} />
              </div>
            )}
            {result.throughput.uploadSamples.length > 0 && (
              <div>
                <div className="text-[10px] mb-1" style={{ color: "var(--text-faint)" }}>Upload Samples</div>
                <MiniBarChart values={result.throughput.uploadSamples} color={c.barGreen} active={phase === "upload"} />
              </div>
            )}
          </div>
        </Card>

        <Card title="Speed Test" subtitle="Run to measure bandwidth">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b pb-2 text-sm" style={{ borderColor: "var(--border-default)" }}>
              <span style={{ color: "var(--text-muted)" }}>Latency</span>
              <span className="font-mono" style={{ color: "var(--text-primary)" }}>{result.latency !== null ? `${result.latency} ms` : "—"}</span>
            </div>
            <div className="flex items-center justify-between border-b pb-2 text-sm" style={{ borderColor: "var(--border-default)" }}>
              <span style={{ color: "var(--text-muted)" }}>Download</span>
              <span className="font-mono" style={{ color: "var(--text-primary)" }}>{result.download !== null ? `${result.download} Mbps` : "—"}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span style={{ color: "var(--text-muted)" }}>Upload</span>
              <span className="font-mono" style={{ color: "var(--text-primary)" }}>{result.upload !== null ? `${result.upload} Mbps` : "—"}</span>
            </div>
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
              <span style={{ color: "var(--text-muted)" }}>{stats ? "Receiving data" : "Connecting..."}</span>
            </div>
            {stats ? (
              <>
                <div className="flex items-center justify-between border-b pb-2 text-sm" style={{ borderColor: "var(--border-default)" }}>
                  <span style={{ color: "var(--text-muted)" }}>Total Packets</span>
                  <span className="font-mono" style={{ color: "var(--text-primary)" }}>{stats.totalPackets.toLocaleString()}</span>
                </div>
                <div className="flex items-center justify-between border-b pb-2 text-sm" style={{ borderColor: "var(--border-default)" }}>
                  <span style={{ color: "var(--text-muted)" }}>Total Alerts</span>
                  <span className="font-mono text-red-500">{stats.totalAlerts}</span>
                </div>
                <div className="flex items-center justify-between border-b pb-2 text-sm" style={{ borderColor: "var(--border-default)" }}>
                  <span style={{ color: "var(--text-muted)" }}>Unique IPs</span>
                  <span className="font-mono" style={{ color: "var(--text-primary)" }}>{stats.uniqueIps}</span>
                </div>
                {stats.inspection && (
                  <div className="flex items-center justify-between text-sm">
                    <span style={{ color: "var(--text-muted)" }}>Packet Rate</span>
                    <span className="font-mono" style={{ color: "var(--text-primary)" }}>{stats.inspection.packetsPerSecond.toFixed(1)}/s</span>
                  </div>
                )}
              </>
            ) : (
              <SkeletonRows rows={4} />
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
                    <span className="font-mono" style={{ color: "var(--text-muted)" }}>{count}</span>
                  </div>
                ))
            ) : (
              <SkeletonRows rows={3} />
            )}
          </div>
        </Card>
      </div>
    </div>
    </DashboardShell>
  );
}

function SkeletonRows({ rows }: { rows: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center justify-between">
          <div className="h-4 w-16 rounded animate-shimmer" style={{ backgroundColor: "var(--bg-muted)" }} />
          <div className="h-4 w-14 rounded animate-shimmer" style={{ backgroundColor: "var(--bg-muted)", animationDelay: `${i * 100}ms` }} />
        </div>
      ))}
    </div>
  );
}

function PingRow({ label, value, unit, highlight }: { label: string; value: number | null; unit: string; highlight?: boolean }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className={highlight ? "font-medium" : ""} style={{ color: highlight ? "var(--text-secondary)" : "var(--text-muted)" }}>{label}</span>
      <span className={`font-mono ${highlight ? "font-semibold" : ""}`} style={{ color: "var(--text-primary)" }}>
        {value !== null ? `${value.toFixed(1)} ${unit}` : "—"}
      </span>
    </div>
  );
}

function MiniBarChart({ values, color, active }: { values: number[]; color: string; active?: boolean }) {
  if (values.length === 0) return null;
  const max = Math.max(...values, 1);
  return (
    <div className="flex items-end gap-px h-8">
      {values.map((v, i) => (
        <div
          key={i}
          className={`flex-1 rounded-t-sm min-w-[3px] transition-all duration-500 ${active ? "animate-shimmer" : ""}`}
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
  const WARMUP = 3;
  const PING_COUNT = 30;
  const samples: number[] = [];
  let losses = 0;
  let dnsTime = 0;
  let dnsSamples = 0;
  let connectTime = 0;
  let connectSamples = 0;

  for (let i = 0; i < WARMUP + PING_COUNT; i++) {
    const t0 = performance.now();
    try {
      const res = await fetch("https://speed.cloudflare.com/__down?bytes=0", {
        cache: "no-store",
        keepalive: true,
        signal: AbortSignal.timeout(3000),
      });
      const elapsed = performance.now() - t0;
      if (res.ok) {
        if (i >= WARMUP) {
          samples.push(elapsed);
        }
      } else {
        if (i >= WARMUP) losses++;
      }
    } catch {
      if (i >= WARMUP) losses++;
    }
  }

  const allPerfEntries = performance.getEntriesByType("resource") as unknown as PerformanceResourceTiming[];
  const perfEntries = allPerfEntries.filter(
    (e) => e.name.includes("speed.cloudflare.com") && e.startTime > 0
  );
  if (perfEntries.length > 0) {
    const recentEntries = perfEntries.slice(-PING_COUNT);
    const dnsTimes = recentEntries.filter((e) => e.domainLookupEnd > 0).map((e) => e.domainLookupEnd - e.domainLookupStart);
    const connTimes = recentEntries.filter((e) => e.connectEnd > 0 && e.connectStart > 0 && e.connectEnd !== e.connectStart).map((e) => e.connectEnd - e.connectStart);
    if (dnsTimes.length > 0) {
      dnsTime = dnsTimes.reduce((a, b) => a + b, 0) / dnsTimes.length;
      dnsSamples = dnsTimes.length;
    }
    if (connTimes.length > 0) {
      connectTime = connTimes.reduce((a, b) => a + b, 0) / connTimes.length;
      connectSamples = connTimes.length;
    }
  }

  if (samples.length === 0) {
    return { min: 0, avg: 0, median: 0, max: 0, jitter: 0, loss: 100, samples: [], dnsTime: dnsSamples > 0 ? Math.round(dnsTime * 10) / 10 : null, connectTime: connectSamples > 0 ? Math.round(connectTime * 10) / 10 : null };
  }

  const sorted = [...samples].sort((a, b) => a - b);
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const avg = samples.reduce((a, b) => a + b, 0) / samples.length;
  const med = median(sorted);

  let jitterSum = 0;
  for (let i = 1; i < samples.length; i++) {
    jitterSum += Math.abs(samples[i] - samples[i - 1]);
  }
  const jitter = jitterSum / Math.max(1, samples.length - 1);
  const loss = Math.round((losses / PING_COUNT) * 100);

  return {
    min: Math.round(min * 10) / 10,
    avg: Math.round(avg * 10) / 10,
    median: Math.round(med * 10) / 10,
    max: Math.round(max * 10) / 10,
    jitter: Math.round(jitter * 10) / 10,
    loss,
    samples: samples.map((s) => Math.round(s * 10) / 10),
    dnsTime: dnsSamples > 0 ? Math.round(dnsTime * 10) / 10 : null,
    connectTime: connectSamples > 0 ? Math.round(connectTime * 10) / 10 : null,
  };
}

async function measureThroughputDownload(): Promise<{ trimmedMean: number; samples: number[]; ttfb: number | null; connectionTimes: number[] }> {
  const WARMUP = 2;
  const SAMPLES = 10;
  const SIZE = 4_194_304;
  const samples: number[] = [];
  const connectionTimes: number[] = [];
  let ttfb = 0;
  let ttfbCount = 0;

  for (let i = 0; i < WARMUP + SAMPLES; i++) {
    const t0 = performance.now();
    try {
      const res = await fetch(`https://speed.cloudflare.com/__down?bytes=${SIZE}`, {
        signal: AbortSignal.timeout(20000),
      });
      if (res.ok) {
        const ttfbElapsed = performance.now() - t0;
        if (i >= WARMUP) {
          if (ttfbElapsed > 0) {
            ttfb += ttfbElapsed;
            ttfbCount++;
          }
        }
        await res.blob();
        const elapsed = performance.now() - t0;
        if (i >= WARMUP && elapsed > 0) {
          samples.push(parseFloat(((SIZE * 8 / elapsed) / 1000).toFixed(1)));
          const allEntries = performance.getEntriesByType("resource") as unknown as PerformanceResourceTiming[];
          const perfEntries = allEntries.filter(
            (e) => e.name.includes("speed.cloudflare.com/__down") && e.connectEnd > 0 && e.connectStart > 0 && e.connectEnd !== e.connectStart
          );
          if (perfEntries.length > 0) {
            connectionTimes.push(perfEntries[perfEntries.length - 1].connectEnd - perfEntries[perfEntries.length - 1].connectStart);
          }
        }
      }
    } catch {
      /* skip failed sample */
    }
  }

  const trimmedMeanVal = samples.length > 0 ? parseFloat(trimmedMean(samples, 0.1).toFixed(1)) : 0;
  return {
    trimmedMean: trimmedMeanVal,
    samples,
    ttfb: ttfbCount > 0 ? parseFloat((ttfb / ttfbCount).toFixed(1)) : null,
    connectionTimes: connectionTimes.map((t) => Math.round(t)),
  };
}

async function measureThroughputUpload(): Promise<{ trimmedMean: number; samples: number[]; ttfb: number | null; connectionTimes: number[] }> {
  const WARMUP = 2;
  const SAMPLES = 10;
  const SIZE = 2_097_152;
  const payload = new TextEncoder().encode("x".repeat(SIZE));
  const samples: number[] = [];
  const connectionTimes: number[] = [];
  let ttfb = 0;
  let ttfbCount = 0;

  for (let i = 0; i < WARMUP + SAMPLES; i++) {
    try {
      const t0 = performance.now();
      const res = await fetch("https://speed.cloudflare.com/__up", {
        method: "POST",
        body: payload,
        signal: AbortSignal.timeout(20000),
      });
      const elapsed = performance.now() - t0;
      if (i >= WARMUP && res.ok && elapsed > 0) {
        samples.push(parseFloat(((SIZE * 8 / elapsed) / 1000).toFixed(1)));
        ttfb += elapsed;
        ttfbCount++;
        const allEntries = performance.getEntriesByType("resource") as unknown as PerformanceResourceTiming[];
        const perfEntries = allEntries.filter(
          (e) => e.name.includes("speed.cloudflare.com/__up") && e.connectEnd > 0 && e.connectStart > 0 && e.connectEnd !== e.connectStart
        );
        if (perfEntries.length > 0) {
          connectionTimes.push(perfEntries[perfEntries.length - 1].connectEnd - perfEntries[perfEntries.length - 1].connectStart);
        }
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
        signal: AbortSignal.timeout(20000),
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

  const trimmedMeanVal = samples.length > 0 ? parseFloat(trimmedMean(samples, 0.1).toFixed(1)) : 0;
  return {
    trimmedMean: trimmedMeanVal,
    samples,
    ttfb: ttfbCount > 0 ? parseFloat((ttfb / ttfbCount).toFixed(1)) : null,
    connectionTimes: connectionTimes.map((t) => Math.round(t)),
  };
}
