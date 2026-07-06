export type Protocol = "TCP" | "UDP" | "ICMP" | "HTTP" | "DNS" | "HTTPS" | "ARP" | "DHCP";

export type AlertSeverity = "critical" | "high" | "medium" | "low";
export type AlertStatus = "new" | "investigating" | "resolved" | "dismissed";

export interface Packet {
  id: string;
  timestamp: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: Protocol;
  length: number;
  ttl: number;
  flags: string[];
  payload: string;
  isMalicious: boolean;
}

export interface Alert {
  id: string;
  timestamp: number;
  title: string;
  description: string;
  severity: AlertSeverity;
  status: AlertStatus;
  packetId: string;
  ruleId: string;
  sourceIp: string;
  destinationIp: string;
  protocol: Protocol;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  signature: string;
  protocol: Protocol | "ANY";
  severity: AlertSeverity;
  enabled: boolean;
  category: string;
  sourcePort: number | null;
  destinationPort: number | null;
  pattern: string;
  createdAt: number;
}

export interface TrafficStats {
  totalPackets: number;
  totalAlerts: number;
  uniqueIps: number;
  protocols: Record<string, number>;
  trafficOverTime: { time: string; normal: number; malicious: number }[];
  topSourceIps: { ip: string; count: number }[];
  topDestPorts: { port: number; count: number }[];
}

export type TimeRange = "1m" | "5m" | "15m" | "1h" | "6h";
