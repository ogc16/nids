import { Packet, Alert, TrafficStats, TimeRange } from "./types";

const MAX_PACKETS = 5000;
const MAX_ALERTS = 1000;

let packets: Packet[] = [];
let alerts: Alert[] = [];

export function getPackets(): Packet[] {
  return packets;
}

export function getAlerts(): Alert[] {
  return alerts;
}

export function addPackets(newPackets: Packet[]): void {
  packets.push(...newPackets);
  if (packets.length > MAX_PACKETS) {
    packets = packets.slice(packets.length - MAX_PACKETS);
  }
}

export function addAlerts(newAlerts: Alert[]): void {
  alerts.push(...newAlerts);
  if (alerts.length > MAX_ALERTS) {
    alerts = alerts.slice(alerts.length - MAX_ALERTS);
  }
}

export function updateAlertStatus(
  alertId: string,
  status: Alert["status"]
): Alert | null {
  const alert = alerts.find((a) => a.id === alertId);
  if (!alert) return null;
  alert.status = status;
  return alert;
}

export function clearAlerts(): void {
  alerts = [];
}

export function getTrafficStats(timeRange: TimeRange = "1m"): TrafficStats {
  const now = Date.now();
  const rangeMap: Record<TimeRange, number> = {
    "1m": 60000,
    "5m": 300000,
    "15m": 900000,
    "1h": 3600000,
    "6h": 21600000,
  };
  const cutoff = now - rangeMap[timeRange];

  const recentPackets = packets.filter((p) => p.timestamp >= cutoff);
  const recentAlerts = alerts.filter((a) => a.timestamp >= cutoff);

  const protocolCounts: Record<string, number> = {};
  recentPackets.forEach((p) => {
    protocolCounts[p.protocol] = (protocolCounts[p.protocol] || 0) + 1;
  });

  const uniqueIps = new Set<string>();
  recentPackets.forEach((p) => {
    uniqueIps.add(p.srcIp);
    uniqueIps.add(p.dstIp);
  });

  const buckets = 20;
  const interval = rangeMap[timeRange] / buckets;
  const trafficOverTime: { time: string; normal: number; malicious: number }[] = [];

  for (let i = 0; i < buckets; i++) {
    const bucketStart = now - rangeMap[timeRange] + i * interval;
    const bucketEnd = bucketStart + interval;
    const bucketPackets = recentPackets.filter(
      (p) => p.timestamp >= bucketStart && p.timestamp < bucketEnd
    );
    trafficOverTime.push({
      time: new Date(bucketStart).toLocaleTimeString(),
      normal: bucketPackets.filter((p) => !p.isMalicious).length,
      malicious: bucketPackets.filter((p) => p.isMalicious).length,
    });
  }

  const srcIpCount = new Map<string, number>();
  recentPackets.forEach((p) => {
    srcIpCount.set(p.srcIp, (srcIpCount.get(p.srcIp) || 0) + 1);
  });
  const topSourceIps = [...srcIpCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, count]) => ({ ip, count }));

  const dstPortCount = new Map<number, number>();
  recentPackets.forEach((p) => {
    dstPortCount.set(p.dstPort, (dstPortCount.get(p.dstPort) || 0) + 1);
  });
  const topDestPorts = [...dstPortCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([port, count]) => ({ port, count }));

  return {
    totalPackets: recentPackets.length,
    totalAlerts: recentAlerts.length,
    uniqueIps: uniqueIps.size,
    protocols: protocolCounts,
    trafficOverTime,
    topSourceIps,
    topDestPorts,
  };
}
