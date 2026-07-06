import { DetectionRule, AlertSeverity, Protocol } from "./types";

const BUILTIN_SIGNATURES: DetectionRule[] = [
  {
    id: "sig_sqli_union", name: "SQL UNION Injection", description: "Detects SQL injection via UNION SELECT in HTTP payloads",
    signature: "SQLI_UNION", protocol: "HTTP", severity: "critical", enabled: true, category: "Web Attack",
    sourcePort: null, destinationPort: null, pattern: "UNION_SELECT", createdAt: 0,
  },
  {
    id: "sig_xss_script", name: "Cross-Site Scripting", description: "Detects XSS script injection attempts",
    signature: "XSS_SCRIPT", protocol: "HTTP", severity: "high", enabled: true, category: "Web Attack",
    sourcePort: null, destinationPort: 80, pattern: "XSS_SCRIPT", createdAt: 0,
  },
  {
    id: "sig_path_traversal", name: "Path Traversal", description: "Detects directory traversal via etc/passwd",
    signature: "PATH_TRAV", protocol: "HTTP", severity: "high", enabled: true, category: "Web Attack",
    sourcePort: null, destinationPort: null, pattern: "ETC_PASSWD", createdAt: 0,
  },
  {
    id: "sig_cmd_exec", name: "Command Execution", description: "Detects command execution via xp_cmdshell",
    signature: "CMD_EXEC", protocol: "ANY", severity: "critical", enabled: true, category: "Exploit",
    sourcePort: null, destinationPort: null, pattern: "CMD_EXEC", createdAt: 0,
  },
  {
    id: "sig_buf_overflow", name: "Buffer Overflow", description: "Detects buffer overflow exploit payloads",
    signature: "BUF_OVERFLOW", protocol: "ANY", severity: "critical", enabled: true, category: "Exploit",
    sourcePort: null, destinationPort: null, pattern: "BUF_OVERFLOW", createdAt: 0,
  },
  {
    id: "sig_malware", name: "Known Malware Signature", description: "Detects known malware byte pattern 9F8E7D6C",
    signature: "MALWARE_9F8E", protocol: "ANY", severity: "critical", enabled: true, category: "Malware",
    sourcePort: null, destinationPort: null, pattern: "MALWARE_SIG_9F8E", createdAt: 0,
  },
  {
    id: "sig_php_inject", name: "PHP Code Injection", description: "Detects PHP code injection in requests",
    signature: "PHP_INJECT", protocol: "HTTP", severity: "high", enabled: true, category: "Web Attack",
    sourcePort: null, destinationPort: null, pattern: "PHP_CODE_INJECTION", createdAt: 0,
  },
  {
    id: "sig_auth_bypass", name: "Authentication Bypass", description: "Detects SQL-based auth bypass attempts",
    signature: "AUTH_BYPASS", protocol: "ANY", severity: "critical", enabled: true, category: "Web Attack",
    sourcePort: null, destinationPort: null, pattern: "AUTH_BYPASS_SQL", createdAt: 0,
  },
  {
    id: "sig_port_scan", name: "Port Scan Probe", description: "Detects SYN-only probes indicative of port scanning",
    signature: "PORT_SCAN", protocol: "TCP", severity: "medium", enabled: true, category: "Reconnaissance",
    sourcePort: null, destinationPort: null, pattern: "PORT_SCAN_SYN", createdAt: 0,
  },
  {
    id: "sig_ssh_brute", name: "SSH Brute Force", description: "Detects SSH brute force login patterns",
    signature: "SSH_BRUTE", protocol: "TCP", severity: "high", enabled: true, category: "Authentication",
    sourcePort: null, destinationPort: 22, pattern: "SSH_BRUTE_FORCE", createdAt: 0,
  },
  {
    id: "sig_dns_tunnel", name: "DNS Tunneling", description: "Detects DNS tunneling via encoded queries",
    signature: "DNS_TUNNEL", protocol: "DNS", severity: "medium", enabled: true, category: "Exfiltration",
    sourcePort: null, destinationPort: 53, pattern: "DNS_TUNNEL_ENCODED", createdAt: 0,
  },
  {
    id: "sig_smb_exploit", name: "SMB EternalBlue Exploit", description: "Detects EternalBlue SMB exploit probes",
    signature: "SMB_EB", protocol: "TCP", severity: "critical", enabled: true, category: "Exploit",
    sourcePort: null, destinationPort: 445, pattern: "SMB_ETERNALBLUE", createdAt: 0,
  },
  {
    id: "sig_admin_probe", name: "Admin Panel Probe", description: "Detects probing of admin panels",
    signature: "ADMIN_PROBE", protocol: "HTTP", severity: "low", enabled: true, category: "Reconnaissance",
    sourcePort: null, destinationPort: 80, pattern: "ADMIN_PANEL_PROBE", createdAt: 0,
  },
  {
    id: "sig_http_sqli", name: "HTTP SQL Injection", description: "Detects SQL injection in HTTP traffic",
    signature: "HTTP_SQLI", protocol: "HTTP", severity: "critical", enabled: true, category: "Web Attack",
    sourcePort: null, destinationPort: null, pattern: "HTTP_SQLI_UNION", createdAt: 0,
  },
];

const now = Date.now();
let rules: DetectionRule[] = BUILTIN_SIGNATURES.map((r) => ({ ...r, createdAt: now }));

export function getRules(): DetectionRule[] {
  return rules;
}

export function getRuleById(id: string): DetectionRule | undefined {
  return rules.find((r) => r.id === id);
}

export function addRule(rule: Omit<DetectionRule, "id" | "createdAt">): DetectionRule {
  const newRule: DetectionRule = {
    ...rule,
    id: `rule_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    createdAt: Date.now(),
  };
  rules.push(newRule);
  return newRule;
}

export function updateRule(id: string, updates: Partial<DetectionRule>): DetectionRule | null {
  const index = rules.findIndex((r) => r.id === id);
  if (index === -1) return null;
  rules[index] = { ...rules[index], ...updates };
  return rules[index];
}

export function deleteRule(id: string): boolean {
  const index = rules.findIndex((r) => r.id === id);
  if (index === -1) return false;
  rules.splice(index, 1);
  return true;
}

export function toggleRule(id: string): DetectionRule | null {
  const rule = rules.find((r) => r.id === id);
  if (!rule) return null;
  rule.enabled = !rule.enabled;
  return rule;
}

export function resetRules(): void {
  rules = [];
}

export function loadBuiltinSignatures(): DetectionRule[] {
  const now = Date.now();
  rules = BUILTIN_SIGNATURES.map((r) => ({ ...r, createdAt: now }));
  return rules;
}

export function getBuiltinSignaturesCount(): number {
  return BUILTIN_SIGNATURES.length;
}
