let agents = [];
let serverRunning = false;
let serverPort = null;

function getRegisteredAgents() { return agents; }

function registerAgent(body) {
  const agent = { id: String(agents.length + 1), name: body.name || `agent-${agents.length + 1}`, type: body.type || 'endpoint', status: 'online', registeredAt: new Date().toISOString() };
  agents.push(agent);
  return agent;
}

function discoverAgents(subnet) {
  const discovered = [{ ip: '10.0.0.1', hostname: 'gateway' }, { ip: '10.0.0.12', hostname: 'server-01' }];
  return discovered;
}

async function collectFromAllAgents() {
  return agents.map((a) => ({ agentId: a.id, status: 'collected' }));
}

function startAgentServer(port) {
  serverPort = port || 9100;
  serverRunning = true;
  return { port: serverPort };
}

function stopAgentServer() {
  serverRunning = false;
  return { status: 'stopped' };
}

function removeAgent(id) {
  agents = agents.filter((a) => a.id !== id);
}

module.exports = { getRegisteredAgents, registerAgent, discoverAgents, collectFromAllAgents, startAgentServer, stopAgentServer, removeAgent };
