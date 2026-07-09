let executions = [];

const builtinPlaybooks = {
  'incident-response': { id: 'incident-response', name: 'Incident Response', description: 'Automated incident investigation and response', steps: ['enrich', 'investigate', 'contain', 'remediate'] },
  'threat-hunt': { id: 'threat-hunt', name: 'Threat Hunt', description: 'Proactive threat hunting across endpoints', steps: ['collect', 'analyze', 'report'] },
  'phishing-analysis': { id: 'phishing-analysis', name: 'Phishing Analysis', description: 'Analyze and respond to phishing reports', steps: ['analyze', 'quarantine', 'notify'] },
};

function getBuiltinPlaybooks() { return builtinPlaybooks; }

function getBuiltinPlaybook(name) { return builtinPlaybooks[name]; }

function startPlaybook(playbookId, context) {
  const executionId = `exec_${Date.now()}`;
  executions.push({ executionId, playbookId, context, status: 'running', startedAt: new Date().toISOString() });
  return executionId;
}

function stopPlaybook(executionId) {
  const exec = executions.find((e) => e.executionId === executionId);
  if (exec) { exec.status = 'stopped'; return true; }
  return false;
}

function listExecutions(filters) {
  let result = [...executions];
  if (filters?.status) result = result.filter((e) => e.status === filters.status);
  if (filters?.playbookId) result = result.filter((e) => e.playbookId === filters.playbookId);
  if (filters?.limit) result = result.slice(0, filters.limit);
  return result;
}

function getPlaybookStatus(executionId) {
  return executions.find((e) => e.executionId === executionId) || null;
}

function clearExecutions() { executions = []; }

module.exports = { getBuiltinPlaybooks, getBuiltinPlaybook, startPlaybook, stopPlaybook, listExecutions, getPlaybookStatus, clearExecutions };
