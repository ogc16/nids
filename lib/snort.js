const path = require('path');
const fs = require('fs');
const { ValidationError, AppError } = require('./errors');

const SNORT_RULE_RE = /^(alert|drop|reject|pass|log|sdrop|activate|dynamic)\s+(\S+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$/i;
const OPTION_RE = /(\w+)\s*:\s*(?:"([^"]*)"|'([^']*)'|(\S+))\s*(?:;|$)/g;

let sidCounter = 1000000;

function parseRule(ruleString) {
  if (typeof ruleString !== 'string' || !ruleString.trim()) {
    throw new ValidationError('Invalid Snort rule: empty or non-string input');
  }

  const match = ruleString.trim().match(SNORT_RULE_RE);
  if (!match) {
    throw new ValidationError('Invalid Snort rule syntax: does not match expected format');
  }

  const [, action, protocol, srcIp, srcPort, destIp, destPort, optionsStr] = match;

  const options = {
    msg: null,
    sid: null,
    rev: null,
    classtype: null,
    priority: null,
    metadata: null,
    content: [],
    reference: []
  };

  let optMatch;
  while ((optMatch = OPTION_RE.exec(optionsStr)) !== null) {
    const key = optMatch[1].toLowerCase();
    const value = optMatch[2] || optMatch[3] || optMatch[4] || '';
    switch (key) {
      case 'msg':
        options.msg = value;
        break;
      case 'sid':
        options.sid = parseInt(value, 10);
        break;
      case 'rev':
        options.rev = parseInt(value, 10);
        break;
      case 'classtype':
        options.classtype = value;
        break;
      case 'priority':
        options.priority = parseInt(value, 10);
        break;
      case 'metadata':
        options.metadata = value;
        break;
      case 'content':
        options.content.push(value);
        break;
      case 'reference':
        options.reference.push(value);
        break;
    }
  }

  return { action, protocol, srcIp, srcPort, direction: '->', destIp, destPort, options };
}

function parseRules(rulesArray) {
  if (!Array.isArray(rulesArray)) {
    throw new ValidationError('Rules must be an array of strings');
  }
  return rulesArray.map((rule, idx) => {
    try {
      return parseRule(rule);
    } catch (err) {
      throw new ValidationError(`Rule at index ${idx} is invalid: ${err.message}`);
    }
  });
}

function ruleToJson(rule) {
  return JSON.stringify(rule, null, 2);
}

function validateRule(ruleString) {
  if (typeof ruleString !== 'string' || !ruleString.trim()) {
    return { valid: false, errors: ['Empty rule string'] };
  }

  const errors = [];

  const hasSemicolon = ruleString.includes(';');
  if (!hasSemicolon) {
    errors.push('Rule must contain semicolons to terminate options');
  }

  const hasParens = ruleString.includes('(') && ruleString.includes(')');
  if (!hasParens) {
    errors.push('Rule options must be enclosed in parentheses');
  }

  const hasDirection = ruleString.includes('->');
  if (!hasDirection) {
    errors.push('Rule must contain direction operator "->"');
  }

  try {
    const parsed = parseRule(ruleString);
    if (!parsed.options.sid) {
      errors.push('Rule must contain a sid option');
    }
    if (!parsed.action || !['alert', 'drop', 'reject', 'pass', 'log', 'sdrop', 'activate', 'dynamic'].includes(parsed.action)) {
      errors.push('Rule must have a valid action (alert, drop, reject, pass, log, sdrop, activate, dynamic)');
    }
    if (!parsed.protocol || !['tcp', 'udp', 'icmp', 'ip', 'http', 'tls'].includes(parsed.protocol)) {
      errors.push('Rule must have a valid protocol (tcp, udp, icmp, ip, http, tls)');
    }
  } catch (err) {
    errors.push(err.message);
  }

  return { valid: errors.length === 0, errors };
}

function generateRuleId() {
  return sidCounter++;
}

function convertToNidsRule(snortRule) {
  const parsed = typeof snortRule === 'string' ? parseRule(snortRule) : snortRule;

  const rule = {
    name: parsed.options.msg || `Snort Rule ${parsed.options.sid || generateRuleId()}`,
    description: parsed.options.msg || '',
    action: parsed.action,
    protocol: parsed.protocol,
    sourceIp: parsed.srcIp,
    sourcePort: parsed.srcPort,
    destIp: parsed.destIp,
    destPort: parsed.destPort,
    direction: parsed.direction,
    patterns: parsed.options.content.map(c => ({ type: 'content', value: c })),
    sid: parsed.options.sid || generateRuleId(),
    rev: parsed.options.rev || 1,
    classtype: parsed.options.classtype || null,
    priority: parsed.options.priority || null,
    metadata: parsed.options.metadata || null,
    references: parsed.options.reference.map(r => ({ source: 'snort', id: r })),
    enabled: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  return rule;
}

function correlateAlert(flow, rules) {
  if (!flow || typeof flow !== 'object') {
    throw new ValidationError('Flow must be an object with protocol, srcIp, dstIp, etc.');
  }
  if (!Array.isArray(rules)) {
    throw new ValidationError('Rules must be an array');
  }

  const matchedRules = [];
  const flowProtocol = (flow.protocol || '').toLowerCase();
  const flowSrcPort = parseInt(flow.srcPort, 10);
  const flowDstPort = parseInt(flow.dstPort, 10);

  for (const rule of rules) {
    let matched = true;
    const confidence = [];

    if (rule.protocol && rule.protocol !== 'ip' && flowProtocol !== rule.protocol.toLowerCase()) {
      matched = false;
    }

    if (matched && rule.destPort && rule.destPort !== 'any') {
      const rulePorts = rule.destPort.split(',').map(p => parseInt(p.trim(), 10));
      if (!rulePorts.includes(flowDstPort)) {
        matched = false;
      } else {
        confidence.push('port_match');
      }
    }

    if (matched && rule.destIp && rule.destIp !== 'any' && !['$EXTERNAL_NET', '$HOME_NET', '$HTTP_SERVERS', '$SQL_SERVERS'].includes(rule.destIp)) {
      if (flow.dstIp && flow.dstIp !== rule.destIp) {
        matched = false;
      } else {
        confidence.push('ip_match');
      }
    }

    if (matched) {
      const confidenceScore = 0.5 + (confidence.length * 0.15);
      matchedRules.push({
        ruleId: rule.sid || rule.id || null,
        ruleName: rule.name || rule.options?.msg || `Rule ${rule.sid || 'unknown'}`,
        confidence: Math.min(confidenceScore, 1.0),
        description: rule.description || rule.options?.msg || `Matched ${rule.protocol || 'unknown'} rule`
      });
    }
  }

  const stats = incrementCorrelationStats(matchedRules.length);

  return {
    matched: matchedRules.length > 0,
    matchedRules,
    stats
  };
}

let correlationStats = {
  totalChecks: 0,
  totalMatches: 0,
  lastCheck: null,
  matchHistory: []
};

function incrementCorrelationStats(matchCount) {
  correlationStats.totalChecks++;
  correlationStats.totalMatches += matchCount;
  correlationStats.lastCheck = new Date().toISOString();
  return { totalChecks: correlationStats.totalChecks, totalMatches: correlationStats.totalMatches };
}

function getCorrelationStats() {
  return { ...correlationStats };
}

function resetCorrelationStats() {
  correlationStats = {
    totalChecks: 0,
    totalMatches: 0,
    lastCheck: null,
    matchHistory: []
  };
}

function importFromFile(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new AppError(404, `Snort rule file not found: ${filePath}`);
  }
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && !l.startsWith('//') && !l.startsWith('include') && !l.startsWith('var ') && !l.startsWith('ipvar ') && !l.startsWith('portvar '));

  const rules = [];
  for (const line of lines) {
    try {
      rules.push(parseRule(line));
    } catch {
      continue;
    }
  }
  return rules;
}

function exportToSnortFormat(rules) {
  if (!Array.isArray(rules)) {
    throw new ValidationError('Rules must be an array');
  }

  return rules.map(rule => {
    const parsed = rule.options ? rule : convertToNidsRule(rule);

    const action = parsed.action || 'alert';
    const protocol = parsed.protocol || 'ip';
    const srcIp = parsed.sourceIp || parsed.srcIp || 'any';
    const srcPort = parsed.sourcePort || parsed.srcPort || 'any';
    const dir = parsed.direction || '->';
    const dstIp = parsed.destIp || parsed.destinationIp || 'any';
    const dstPort = parsed.destPort || parsed.destinationPort || 'any';

    const opts = [];

    const msg = parsed.name || parsed.options?.msg || (parsed.description || '');
    if (msg) opts.push(`msg:"${msg}"`);

    if (parsed.patterns && Array.isArray(parsed.patterns)) {
      for (const p of parsed.patterns) {
        if (p.type === 'content' && p.value) {
          opts.push(`content:"${p.value}"`);
        }
      }
    } else if (parsed.options?.content) {
      for (const c of parsed.options.content) {
        opts.push(`content:"${c}"`);
      }
    }

    const sid = parsed.sid || parsed.options?.sid;
    if (sid) opts.push(`sid:${sid}`);

    const rev = parsed.rev || parsed.options?.rev;
    if (rev) opts.push(`rev:${rev}`);

    const classtype = parsed.classtype || parsed.options?.classtype;
    if (classtype) opts.push(`classtype:${classtype}`);

    const priority = parsed.priority || parsed.options?.priority;
    if (priority) opts.push(`priority:${priority}`);

    const metadata = parsed.metadata || parsed.options?.metadata;
    if (metadata) opts.push(`metadata:${metadata}`);

    if (parsed.references && Array.isArray(parsed.references)) {
      for (const ref of parsed.references) {
        const refId = ref.id || ref;
        opts.push(`reference:${refId}`);
      }
    } else if (parsed.options?.reference) {
      for (const ref of parsed.options.reference) {
        opts.push(`reference:${ref}`);
      }
    }

    return `${action} ${protocol} ${srcIp} ${srcPort} ${dir} ${dstIp} ${dstPort} (${opts.join('; ')};)`;
  }).join('\n');
}

const sampleRules = [
  { raw: 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"SQL Injection Attempt"; content:"union select"; content:"from"; sid:1000001; rev:1; classtype:attempted-admin; priority:1;)', category: 'SQL Injection' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Cross-Site Scripting Attempt"; content:"<script"; nocase; sid:1000002; rev:1; classtype:web-application-attack; priority:1;)', category: 'XSS' },
  { raw: 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"C2 Beaconing HTTP"; content:"GET"; content:"/gate.php"; sid:1000003; rev:1; classtype:command-and-control; priority:1; metadata:C2;)', category: 'C2 Beaconing' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Local File Inclusion Attempt"; content:"../"; sid:1000004; rev:1; classtype:web-application-attack; priority:2;)', category: 'Web Attack' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server; detection_filter:track by_src, count 30, seconds 60; sid:1000005; rev:1; classtype:attempted-recon; priority:2;)', category: 'Brute Force' },
  { raw: 'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"DNS Tunneling Detection"; content:"|00 00 00 00 00 00 00 00|"; within:200; sid:1000006; rev:1; classtype:command-and-control; priority:1; metadata:DNS_TUNNEL;)', category: 'DNS Tunneling' },
  { raw: 'alert tcp $HOME_NET any -> $EXTERNAL_NET 445 (msg:"SMB Outbound Exploit Attempt"; content:"|FF 53 4D 42|"; sid:1000007; rev:1; classtype:attempted-admin; priority:1; metadata:SMB;)', category: 'SMB Exploit' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"RDP Brute Force Login"; flow:to_server; detection_filter:track by_src, count 20, seconds 30; sid:1000008; rev:1; classtype:attempted-user; priority:2; metadata:RDP;)', category: 'RDP Abuse' },
  { raw: 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Malware Outbound HTTPS Beacon"; content:"|16 03 01 00|"; sid:1000009; rev:1; classtype:command-and-control; priority:1; metadata:MALWARE;)', category: 'Malware Outbound' },
  { raw: 'alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"Port Scan Detection"; ip_proto:6; detection_filter:track by_src, count 25, seconds 10; sid:1000010; rev:1; classtype:attempted-recon; priority:2; metadata:SCAN;)', category: 'Port Scanning' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"FTP Brute Force Attempt"; flow:to_server; detection_filter:track by_src, count 15, seconds 30; sid:1000011; rev:1; classtype:attempted-user; priority:2;)', category: 'Brute Force' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 1433 (msg:"MSSQL Injection Attempt"; content:"exec xp_cmdshell"; sid:1000012; rev:1; classtype:attempted-admin; priority:1; metadata:SQL;)', category: 'SQL Injection' },
  { raw: 'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"DNS Query for Known Malicious Domain"; content:"evil"; content:"com"; sid:1000013; rev:1; classtype:command-and-control; priority:1; metadata:DNS_BL;)', category: 'DNS Threat' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Command Injection via HTTP"; content:"cmd="; content:"/c"; content:"ping"; sid:1000014; rev:1; classtype:attempted-admin; priority:1;)', category: 'Command Injection' },
  { raw: 'alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"Spam Email Relay Detection"; content:"RCPT TO"; content:"TO"; sid:1000015; rev:1; classtype:policy-violation; priority:3; metadata:SPAM;)', category: 'Spam Relay' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 6379 (msg:"Redis Unauthorized Access Attempt"; content:"CONFIG SET"; sid:1000016; rev:1; classtype:attempted-admin; priority:1; metadata:REDIS;)', category: 'Database Attack' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 27017 (msg:"MongoDB Exposed Detection"; content:"isMaster"; sid:1000017; rev:1; classtype:attempted-recon; priority:2; metadata:MONGODB;)', category: 'Database Attack' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Path Traversal via URI"; content:"/../../../"; sid:1000018; rev:1; classtype:web-application-attack; priority:2;)', category: 'Web Attack' },
  { raw: 'alert udp $HOME_NET any -> $EXTERNAL_NET 123 (msg:"NTP Amplification DDoS Attempt"; content:"|17 00 03 2a|"; sid:1000019; rev:1; classtype:attempted-dos; priority:2; metadata:DDoS;)', category: 'DDoS' },
  { raw: 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Log4j JNDI Exploit Attempt"; content:"${jndi:ldap://"; sid:1000020; rev:1; classtype:attempted-admin; priority:1; metadata:LOG4J;)', category: 'Vulnerability Exploit' }
].map(s => {
  const parsed = parseRule(s.raw);
  parsed.category = s.category;
  return parsed;
});

module.exports = {
  parseRule,
  parseRules,
  ruleToJson,
  validateRule,
  generateRuleId,
  convertToNidsRule,
  correlateAlert,
  getCorrelationStats,
  resetCorrelationStats,
  importFromFile,
  exportToSnortFormat,
  sampleRules
};
