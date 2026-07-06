const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const agent = require('../lib/agent');

router.get('/agents', authenticate, (req, res, next) => {
  try {
    res.json(agent.getRegisteredAgents());
  } catch (err) { next(err); }
});

router.post('/agents/register', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = agent.registerAgent(req.body);
    audit('agent_registered', req, { name: req.body.name });
    res.status(201).json(result);
  } catch (err) { next(err); }
});

router.post('/agents/discover', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const { subnet } = req.body;
    if (!subnet) return res.status(400).json({ error: 'subnet is required' });
    const result = agent.discoverAgents(subnet);
    audit('agent_discovery', req, { subnet });
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/agents/collect', authenticate, authorize('admin', 'analyst'), async (req, res, next) => {
  try {
    const result = await agent.collectFromAllAgents();
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/agents/server/start', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = agent.startAgentServer(req.body?.port || 9100);
    audit('agent_server_started', req, { port: result.port });
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/agents/server/stop', authenticate, authorize('admin'), (req, res, next) => {
  try {
    agent.stopAgentServer();
    audit('agent_server_stopped', req);
    res.json({ status: 'stopped' });
  } catch (err) { next(err); }
});

router.delete('/agents/:id', authenticate, authorize('admin'), (req, res, next) => {
  try {
    agent.removeAgent(req.params.id);
    audit('agent_removed', req, { id: req.params.id });
    res.status(204).send();
  } catch (err) { next(err); }
});

module.exports = router;
