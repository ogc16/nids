import { DetectionRule, AlertSeverity, Protocol } from "./types";

const DEFAULT_RULES: DetectionRule[] = [
  {
    id: "rule_sqli_001",
    name: "SQL Injection Attempt",
    description: "Detects common SQL injection patterns in packet payloads",
    signature: "SQLI_SIGNATURE",
    protocol: "ANY",
    severity: "critical",
    enabled: true,
    category: "Web Attack",
    sourcePort: null,
    destinationPort: null,
    pattern: "SQLI_",
    createdAt: Date.now(),
  },
  {
    id: "rule_xss_001",
    name: "Cross-Site Scripting",
    description: "Detects XSS attack patterns in HTTP traffic",
    signature: "XSS_SIGNATURE",
    protocol: "ANY",
    severity: "high",
    enabled: true,
    category: "Web Attack",
    sourcePort: null,
    destinationPort: 80,
    pattern: "XSS_SCRIPT_ALERT",
    createdAt: Date.now(),
  },
  {
    id: "rule_path_001",
    name: "Path Traversal Attempt",
    description: "Detects directory traversal attacks",
    signature: "PATH_TRAVERSAL",
    protocol: "ANY",
    severity: "high",
    enabled: true,
    category: "Web Attack",
    sourcePort: null,
    destinationPort: null,
    pattern: "PATH_TRAVERSAL",
    createdAt: Date.now(),
  },
  {
    id: "rule_portscan_001",
    name: "Port Scan Probe",
    description: "Detects SYN packets that may indicate port scanning",
    signature: "PORT_SCAN",
    protocol: "TCP",
    severity: "medium",
    enabled: true,
    category: "Reconnaissance",
    sourcePort: null,
    destinationPort: null,
    pattern: "PORT_SCAN_SYN",
    createdAt: Date.now(),
  },
  {
    id: "rule_malware_001",
    name: "Known Malware Signature",
    description: "Detects known malware byte patterns",
    signature: "MALWARE_SIG",
    protocol: "ANY",
    severity: "critical",
    enabled: true,
    category: "Malware",
    sourcePort: null,
    destinationPort: null,
    pattern: "MALWARE_SIG_9",
    createdAt: Date.now(),
  },
  {
    id: "rule_overflow_001",
    name: "Buffer Overflow Attempt",
    description: "Detects potential buffer overflow payloads",
    signature: "BUFFER_OVERFLOW",
    protocol: "ANY",
    severity: "critical",
    enabled: true,
    category: "Exploit",
    sourcePort: null,
    destinationPort: null,
    pattern: "BUF_OVERFLOW",
    createdAt: Date.now(),
  },
  {
    id: "rule_bruteforce_001",
    name: "SSH Brute Force",
    description: "Detects SSH brute force login attempts",
    signature: "SSH_BRUTE",
    protocol: "ANY",
    severity: "high",
    enabled: true,
    category: "Authentication",
    sourcePort: null,
    destinationPort: 22,
    pattern: "SSH_BRUTE_FORCE",
    createdAt: Date.now(),
  },
  {
    id: "rule_dns_tunnel_001",
    name: "DNS Tunneling",
    description: "Detects potential DNS tunneling activity",
    signature: "DNS_TUNNEL",
    protocol: "DNS",
    severity: "medium",
    enabled: true,
    category: "Exfiltration",
    sourcePort: null,
    destinationPort: 53,
    pattern: "DNS_TUNNEL",
    createdAt: Date.now(),
  },
  {
    id: "rule_smb_exploit_001",
    name: "SMB Exploit (EternalBlue)",
    description: "Detects SMB exploit payloads like EternalBlue",
    signature: "SMB_EXPLOIT",
    protocol: "ANY",
    severity: "critical",
    enabled: true,
    category: "Exploit",
    sourcePort: null,
    destinationPort: 445,
    pattern: "SMB_ETERNALBLUE",
    createdAt: Date.now(),
  },
  {
    id: "rule_php_cmd_001",
    name: "PHP Code Injection",
    description: "Detects PHP code injection attempts",
    signature: "PHP_CMD",
    protocol: "ANY",
    severity: "high",
    enabled: true,
    category: "Web Attack",
    sourcePort: null,
    destinationPort: null,
    pattern: "PHP_CODE_INJECTION",
    createdAt: Date.now(),
  },
  {
    id: "rule_admin_probe_001",
    name: "Admin Panel Probe",
    description: "Detects probing of admin/WordPress panels",
    signature: "ADMIN_PROBE",
    protocol: "ANY",
    severity: "low",
    enabled: true,
    category: "Reconnaissance",
    sourcePort: null,
    destinationPort: 80,
    pattern: "ADMIN_PANEL_PROBE",
    createdAt: Date.now(),
  },
  {
    id: "rule_cmd_exec_001",
    name: "Command Execution via xp_cmdshell",
    description: "Detects xp_cmdshell abuse attempts",
    signature: "CMD_EXEC",
    protocol: "ANY",
    severity: "critical",
    enabled: true,
    category: "Exploit",
    sourcePort: null,
    destinationPort: null,
    pattern: "CMD_EXEC_XP",
    createdAt: Date.now(),
  },
];

let rules: DetectionRule[] = [...DEFAULT_RULES];

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
  rules = [...DEFAULT_RULES];
}
