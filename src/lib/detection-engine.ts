import { Packet, Alert, DetectionRule, AlertSeverity, Protocol } from "./types";

let alertCounter = 0;

function generateAlertId(): string {
  alertCounter++;
  return `alert_${Date.now()}_${alertCounter}`;
}

function severityScore(severity: AlertSeverity): number {
  switch (severity) {
    case "critical": return 4;
    case "high": return 3;
    case "medium": return 2;
    case "low": return 1;
  }
}

function matchPort(rulePort: number | null, packetPort: number): boolean {
  return rulePort === null || rulePort === packetPort;
}

function matchProtocol(ruleProtocol: Protocol | "ANY", packetProtocol: Protocol): boolean {
  return ruleProtocol === "ANY" || ruleProtocol === packetProtocol;
}

function matchPattern(payload: string, pattern: string): boolean {
  if (!pattern) return true;
  return payload.toLowerCase().includes(pattern.toLowerCase());
}

function matchRule(packet: Packet, rule: DetectionRule): boolean {
  if (!rule.enabled) return false;
  if (!matchProtocol(rule.protocol, packet.protocol)) return false;
  if (!matchPort(rule.sourcePort, packet.srcPort)) return false;
  if (!matchPort(rule.destinationPort, packet.dstPort)) return false;
  if (!matchPattern(packet.payload, rule.pattern)) return false;
  return true;
}

export function evaluatePacket(
  packet: Packet,
  rules: DetectionRule[]
): Alert | null {
  if (!packet.isMalicious) return null;

  let matchedRule: DetectionRule | null = null;
  let highestScore = -1;

  for (const rule of rules) {
    if (matchRule(packet, rule)) {
      const score = severityScore(rule.severity);
      if (score > highestScore) {
        highestScore = score;
        matchedRule = rule;
      }
    }
  }

  if (!matchedRule) return null;

  return {
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
  };
}

export function evaluateBatch(packets: Packet[], rules: DetectionRule[]): Alert[] {
  const alerts: Alert[] = [];
  for (const packet of packets) {
    if (packet.isMalicious) {
      const alert = evaluatePacket(packet, rules);
      if (alert) alerts.push(alert);
    }
  }
  return alerts;
}
