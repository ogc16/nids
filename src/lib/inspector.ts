import { cpus } from "os";
import { Packet, Alert, DetectionRule, ParsedProtocol, InspectionMetrics } from "./types";
import { parsePacket } from "./protocol-parser";

let alertCounter = 0;

function generateAlertId(): string {
  alertCounter++;
  return `alert_${Date.now()}_${alertCounter}`;
}

const severityScoreMap: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

interface WorkerQueue {
  concurrency: number;
  running: number;
  queue: Array<{
    packets: Packet[];
    rules: DetectionRule[];
    resolve: (result: InspectionResult[]) => void;
  }>;
}

interface InspectionResult {
  packetId: string;
  alerts: Alert[];
  parsed: ParsedProtocol;
}

const metrics: InspectionMetrics = {
  packetsInspected: 0,
  packetsPerSecond: 0,
  avgInspectionMs: 0,
  activeWorkers: 0,
  queueDepth: 0,
};

let totalInspectionTime = 0;
let metricsInterval: ReturnType<typeof setInterval> | null = null;

if (typeof setInterval !== "undefined") {
  metricsInterval = setInterval(() => {
    const prev = metrics.packetsInspected;
    setTimeout(() => {
      metrics.packetsPerSecond = metrics.packetsInspected - prev;
    }, 0);
    metrics.queueDepth = queue.queue.length;
  }, 1000);
}

const queue: WorkerQueue = {
  concurrency: Math.max(1, Math.min(8, cpus().length)),
  running: 0,
  queue: [],
};

function processChunk(packets: Packet[], rules: DetectionRule[]): InspectionResult[] {
  const results: InspectionResult[] = [];

  for (const packet of packets) {
    const parsed = parsePacket(packet);
    const alerts: Alert[] = [];

    if (packet.isMalicious) {
      let matchedRule: DetectionRule | null = null;
      let highestScore = -1;

      for (const rule of rules) {
        if (!rule.enabled) continue;
        if (!matchProtocol(rule.protocol, packet.protocol)) continue;
        if (!matchPort(rule.sourcePort, packet.srcPort)) continue;
        if (!matchPort(rule.destinationPort, packet.dstPort)) continue;
        if (!matchPattern(packet.payload, rule.pattern)) continue;
        if (!matchEnhanced(rule, packet, parsed)) continue;

        const score = severityScoreMap[rule.severity] || 0;
        if (score > highestScore) {
          highestScore = score;
          matchedRule = rule;
        }
      }

      if (matchedRule) {
        alerts.push({
          id: generateAlertId(),
          timestamp: Date.now(),
          title: `${matchedRule.name} detected from ${packet.srcIp}`,
          description: `Packet matched rule "${matchedRule.name}" - ${matchedRule.description}. Protocol: ${packet.protocol}, Src: ${packet.srcIp}:${packet.srcPort} -> Dst: ${packet.dstIp}:${packet.dstPort}`,
          severity: matchedRule.severity,
          status: "new",
          packetId: packet.id,
          ruleId: matchedRule.id,
          sourceIp: packet.srcIp,
          destinationIp: packet.dstIp,
          protocol: packet.protocol,
        });
      }
    }

    results.push({ packetId: packet.id, alerts, parsed });
  }

  return results;
}

function matchProtocol(ruleProtocol: string, packetProtocol: string): boolean {
  return ruleProtocol === "ANY" || ruleProtocol === packetProtocol;
}

function matchPort(rulePort: number | null, packetPort: number): boolean {
  return rulePort === null || rulePort === packetPort;
}

function matchPattern(payload: string, pattern: string): boolean {
  if (!pattern) return true;
  return payload.toLowerCase().includes(pattern.toLowerCase());
}

function matchEnhanced(rule: DetectionRule, packet: Packet, parsed: ParsedProtocol): boolean {
  const hasRegex = rule.pattern.startsWith("/") && rule.pattern.endsWith("/");
  if (hasRegex) {
    try {
      const regex = new RegExp(rule.pattern.slice(1, -1), "i");
      if (!regex.test(packet.payload)) return false;
    } catch {
      return true;
    }
  }

  if (rule.protocol === "HTTP" || rule.protocol === "HTTPS") {
    if (rule.category === "Web Attack") {
      const uri = parsed.httpUri || "";
      const method = parsed.httpMethod || "";
      if (method && !method.match(/GET|POST|PUT/i)) return false;
      if (uri && uri.includes("..")) return true;
    }
  }

  if (rule.protocol === "DNS") {
    if (parsed.dnsQueryName) {
      const domain = parsed.dnsQueryName.toLowerCase();
      const hasSuspicious = domain.includes("tunnel") || domain.split(".").some((p: string) => p.length > 20);
      if (hasSuspicious) return true;
    }
  }

  return true;
}

export function processBatch(packets: Packet[], rules: DetectionRule[]): InspectionResult[] {
  const start = performance.now();
  const results = processChunk(packets, rules);
  const elapsed = performance.now() - start;

  metrics.packetsInspected += packets.length;
  totalInspectionTime += elapsed;
  metrics.avgInspectionMs = totalInspectionTime / metrics.packetsInspected;
  metrics.activeWorkers = queue.concurrency;

  return results;
}

export async function processBatchAsync(packets: Packet[], rules: DetectionRule[]): Promise<InspectionResult[]> {
  const chunkSize = Math.max(1, Math.ceil(packets.length / queue.concurrency));
  const chunks: Packet[][] = [];

  for (let i = 0; i < packets.length; i += chunkSize) {
    chunks.push(packets.slice(i, i + chunkSize));
  }

  const start = performance.now();
  const results = await Promise.all(
    chunks.map((chunk) =>
      new Promise<InspectionResult[]>((resolve) => {
        queue.queue.push({
          packets: chunk,
          rules,
          resolve,
        });
        dequeue();
      })
    )
  );
  const elapsed = performance.now() - start;

  metrics.packetsInspected += packets.length;
  totalInspectionTime += elapsed;
  metrics.avgInspectionMs = totalInspectionTime / metrics.packetsInspected;
  metrics.activeWorkers = queue.concurrency;
  metrics.queueDepth = queue.queue.length;

  return results.flat();
}

function dequeue(): void {
  if (queue.running >= queue.concurrency || queue.queue.length === 0) return;
  queue.running++;

  const job = queue.queue.shift()!;
  setTimeout(() => {
    const result = processChunk(job.packets, job.rules);
    queue.running--;
    job.resolve(result);
    dequeue();
  }, 0);
}

export function getInspectionMetrics(): InspectionMetrics {
  return { ...metrics };
}

export function setConcurrency(n: number): void {
  queue.concurrency = Math.max(1, Math.min(16, n));
}
