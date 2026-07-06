import { Packet, ParsedProtocol } from "./types";

export function parsePacket(packet: Packet): ParsedProtocol {
  const payload = packet.payload || "";

  if (packet.protocol === "HTTP" || packet.protocol === "HTTPS") {
    return parseHttp(payload);
  }
  if (packet.protocol === "DNS") {
    return parseDns(payload);
  }
  if (packet.protocol === "TCP") {
    return parseTcp(packet);
  }

  return { hasPayload: payload.length > 0 };
}

function parseHttp(payload: string): ParsedProtocol {
  const result: ParsedProtocol = { hasPayload: payload.length > 0 };

  const reqMatch = payload.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+(HTTP\/[\d.]+)/);
  if (reqMatch) {
    result.httpMethod = reqMatch[1];
    result.httpUri = reqMatch[2];
    result.httpVersion = reqMatch[3];
  }

  const hostMatch = payload.match(/[|]\s*Host:\s*(\S+)/i);
  if (hostMatch) result.httpHost = hostMatch[1];

  const uaMatch = payload.match(/[|]\s*User-Agent:\s*(.+?)(?:[|]|$)/i);
  if (uaMatch) result.httpUserAgent = uaMatch[1].trim();

  return result;
}

function parseDns(payload: string): ParsedProtocol {
  const result: ParsedProtocol = { hasPayload: payload.length > 0 };

  const queryMatch = payload.match(/query\s+0x[\da-f]+\s+(\w+)\s+(\S+)/i);
  if (queryMatch) {
    result.dnsQueryType = queryMatch[1].toUpperCase();
    result.dnsQueryName = queryMatch[2];
  }

  return result;
}

function parseTcp(packet: Packet): ParsedProtocol {
  const result: ParsedProtocol = { hasPayload: packet.payload.length > 0 };

  const syn = packet.flags.includes("SYN");
  const ack = packet.flags.includes("ACK");
  const fin = packet.flags.includes("FIN");
  const rst = packet.flags.includes("RST");
  const psh = packet.flags.includes("PSH");

  result.tcpFlagsParsed = { syn, ack, fin, rst, psh };

  if (packet.dstPort === 443 || packet.dstPort === 8443) {
    const sniMatch = packet.payload.match(/TLS[\s\w.]+\s+(\S+?)(?:\s|$)/);
    if (sniMatch) result.tlsSni = sniMatch[1];
  }

  return result;
}
