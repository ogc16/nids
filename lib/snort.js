const sampleRules = [
  'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"WEB-MISC SQL Injection Attempt"; content:"UNION SELECT"; nocase; sid:1000001;)',
  'alert tcp $EXTERNAL_NET 80 -> $HOME_NET any (msg:"WEB-MISC XSS Attempt"; content:"<script>"; nocase; sid:1000002;)',
];

function validateRule(rule) {
  return { valid: true, errors: [] };
}

function parseRule(rule) {
  return { action: 'alert', protocol: 'tcp', src: '$HOME_NET', srcPort: 'any', direction: '->', dst: '$EXTERNAL_NET', dstPort: '80', options: [{ msg: 'Parsed rule' }] };
}

function convertToNidsRule(snortRule) {
  return { name: 'Converted Rule', description: 'Imported from Snort', protocol: 'TCP', severity: 'medium', pattern: snortRule.slice(0, 100), enabled: true };
}

function correlateAlert(flow, rules) {
  return { flow, matchedRules: rules ? rules.length : 0, correlationScore: 0.75 };
}

function getCorrelationStats() {
  return { totalCorrelated: 150, falsePositives: 12, truePositives: 138, accuracy: 0.92 };
}

module.exports = { sampleRules, validateRule, parseRule, convertToNidsRule, correlateAlert, getCorrelationStats };
