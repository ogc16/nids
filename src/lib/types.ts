export type Protocol = "TCP" | "UDP" | "ICMP" | "HTTP" | "DNS" | "HTTPS" | "ARP" | "DHCP";

export type AssetCriticality = "critical" | "high" | "medium" | "low";
export type AssetType = "server" | "workstation" | "database" | "firewall" | "router" | "service" | "other";

export interface NetworkAsset {
  id: string;
  name: string;
  nickname: string;
  ip: string;
  type: AssetType;
  group: string;
  tags: string[];
  criticality: AssetCriticality;
  description: string;
  createdAt: number;
}

export interface AssetTraffic {
  assetId: string;
  totalPackets: number;
  incomingPackets: number;
  outgoingPackets: number;
  totalAlerts: number;
  bytesIn: number;
  bytesOut: number;
  protocols: Record<string, number>;
  topTalkers: { ip: string; count: number }[];
  lastSeen: number;
}


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

export interface ParsedProtocol {
  httpMethod?: string;
  httpUri?: string;
  httpVersion?: string;
  httpHost?: string;
  httpUserAgent?: string;
  dnsQueryName?: string;
  dnsQueryType?: string;
  tcpFlagsParsed?: { syn: boolean; ack: boolean; fin: boolean; rst: boolean; psh: boolean };
  tlsSni?: string;
  hasPayload: boolean;
}

export interface InspectionMetrics {
  packetsInspected: number;
  packetsPerSecond: number;
  avgInspectionMs: number;
  activeWorkers: number;
  queueDepth: number;
}

export interface TrafficStats {
  totalPackets: number;
  totalAlerts: number;
  uniqueIps: number;
  protocols: Record<string, number>;
  trafficOverTime: { time: string; normal: number; malicious: number }[];
  topSourceIps: { ip: string; count: number }[];
  topDestPorts: { port: number; count: number }[];
  inspection?: InspectionMetrics;
}

export type TimeRange = "1m" | "5m" | "15m" | "1h" | "6h";
