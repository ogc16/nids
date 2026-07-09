const tactics = [
  { id: 'TA0043', name: 'Reconnaissance', techniques: 10 },
  { id: 'TA0042', name: 'Resource Development', techniques: 8 },
  { id: 'TA0001', name: 'Initial Access', techniques: 12 },
  { id: 'TA0002', name: 'Execution', techniques: 14 },
  { id: 'TA0003', name: 'Persistence', techniques: 20 },
  { id: 'TA0004', name: 'Privilege Escalation', techniques: 14 },
  { id: 'TA0005', name: 'Defense Evasion', techniques: 42 },
  { id: 'TA0006', name: 'Credential Access', techniques: 18 },
  { id: 'TA0007', name: 'Discovery', techniques: 30 },
  { id: 'TA0008', name: 'Lateral Movement', techniques: 10 },
  { id: 'TA0009', name: 'Collection', techniques: 16 },
  { id: 'TA0011', name: 'Command and Control', techniques: 18 },
  { id: 'TA0010', name: 'Exfiltration', techniques: 10 },
  { id: 'TA0040', name: 'Impact', techniques: 14 },
];

const techniques = tactics.flatMap((t) =>
  Array.from({ length: 3 }, (_, i) => ({
    id: `${t.id}-T${1000 + i}`,
    name: `${t.name} Technique ${i + 1}`,
    tactic: t.name,
  }))
);

function getTactics() { return tactics; }
function getTechniques() { return techniques; }
function getCoverage() {
  return { totalTactics: tactics.length, coveredTactics: Math.floor(tactics.length * 0.7), coveragePercent: 70, tactics: tactics.map((t) => ({ ...t, covered: true })) };
}
function getMatrix() { return { tactics }; }
function analyze(type, data) {
  return { type, techniques: [{ id: 'T1059', name: 'Command and Scripting Interpreter', confidence: 0.85 }] };
}

module.exports = { getTactics, getTechniques, getCoverage, getMatrix, analyze };
