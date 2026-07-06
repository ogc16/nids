import { Packet, Protocol } from "./types";

const privateIps = [
  "10.0.0.1", "10.0.0.12", "10.0.0.45", "10.0.1.5", "10.0.1.22",
  "192.168.1.1", "192.168.1.10", "192.168.1.15", "192.168.1.100",
  "192.168.1.105", "192.168.2.50", "172.16.0.1", "172.16.0.20",
];

const externalIps = [
  "8.8.8.8", "8.8.4.4", "1.1.1.1", "142.250.80.46", "104.16.132.229",
  "185.199.108.153", "140.82.121.3", "151.101.1.140", "34.120.85.73",
  "35.186.224.25", "52.84.121.67", "198.51.100.3", "198.51.100.7",
  "203.0.113.5", "45.33.32.156", "91.108.56.100",
];

const maliciousIps = [
  "185.220.101.42", "103.235.46.95", "45.155.205.233", "5.188.62.18",
  "91.121.89.115", "194.26.29.119", "185.165.29.35", "37.120.237.115",
  "162.247.74.201", "198.98.54.20",
];

const protocols: Protocol[] = ["TCP", "UDP", "ICMP", "HTTP", "DNS", "HTTPS", "ARP", "DHCP"];

const commonPorts: Record<string, number[]> = {
  TCP: [22, 80, 443, 8080, 3306, 5432, 3389, 25, 21, 8443, 3000, 9090, 27017, 6379],
  UDP: [53, 67, 68, 123, 161, 162, 514, 500, 4500, 5353],
  HTTP: [80, 8080, 3000, 8000],
  HTTPS: [443, 8443],
  DNS: [53],
  ICMP: [0, 8],
  ARP: [0],
  DHCP: [67, 68],
};

let packetCounter = 0;

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function hexPayload(length: number): string {
  const hex = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < length; i++) {
    out += hex[Math.floor(Math.random() * 16)];
  }
  return out;
}

function normalPayload(protocol: Protocol): string {
  if (protocol === "HTTP") return "GET /index.html HTTP/1.1|Host: example.com|User-Agent: Mozilla/5.0";
  if (protocol === "DNS") return "Standard query 0x" + randInt(1000, 9999) + " A example.com";
  if (protocol === "HTTPS") return "TLS 1.3 ClientHello (encrypted)";
  if (protocol === "DHCP") return "DHCP Discover - Transaction ID 0x" + randInt(100000, 999999).toString(16);
  if (protocol === "ARP") return "Who has " + pick(externalIps) + "? Tell " + pick(privateIps);
  return "Standard " + protocol + " payload - seq:" + randInt(10000, 99999);
}

const attackSignatures = [
  "SQLI_UNION_SELECT",
  "PATH_TRAVERSAL_ETC_PASSWD",
  "XSS_SCRIPT_ALERT",
  "CMD_EXEC_XP_CMDSHELL",
  "FILE_ACCESS_SHADOW",
  "PHP_CODE_INJECTION",
  "AUTH_BYPASS_SQL",
  "MALWARE_SIG_9F8E7D6C",
  "BUF_OVERFLOW_PATTERN",
  "PORT_SCAN_SYN_PROBE",
  "ADMIN_PANEL_PROBE",
  "SSH_BRUTE_FORCE_ATTEMPT",
  "DNS_TUNNEL_ENCODED",
  "HTTP_SQLI_UNION_NULL",
  "SMB_ETERNALBLUE_PROBE",
];

function generateAttackPayload(): string {
  return pick(attackSignatures) + "_" + hexPayload(8);
}

function isMaliciousPacket(): boolean {
  return Math.random() < 0.08;
}

export function generatePacket(): Packet {
  packetCounter++;
  const id = `pkt_${Date.now()}_${packetCounter}`;
  const malicious = isMaliciousPacket();
  const protocol = pick(protocols);

  const useMaliciousSrc = malicious && Math.random() < 0.7;
  const srcIp = useMaliciousSrc ? pick(maliciousIps) : pick(privateIps);
  const dstIp = malicious && !useMaliciousSrc ? pick(maliciousIps) : pick(externalIps);

  const ports = commonPorts[protocol] || [80];
  const srcPort = randInt(1024, 65535);
  const dstPort = pick(ports);

  const length = malicious ? randInt(64, 1500) : randInt(40, 1024);
  const ttl = randInt(32, 255);

  const flags: string[] = [];
  if (protocol === "TCP" || protocol === "HTTP" || protocol === "HTTPS") {
    if (malicious && Math.random() < 0.5) flags.push("SYN");
    else flags.push(...["SYN", "ACK"]);
    if (Math.random() < 0.3) flags.push("PSH");
    if (malicious && Math.random() < 0.3) flags.push("RST");
    if (Math.random() < 0.1) flags.push("FIN");
  }

  const payload = malicious ? generateAttackPayload() : normalPayload(protocol);

  return {
    id,
    timestamp: Date.now(),
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    protocol,
    length,
    ttl,
    flags,
    payload,
    isMalicious: malicious,
  };
}

export function generateBatch(count: number): Packet[] {
  return Array.from({ length: count }, () => generatePacket());
}
