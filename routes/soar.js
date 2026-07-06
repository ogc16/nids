const express = require('express');
const router = express.Router();
const { authenticate, authorize, optionalAuth } = require('../lib/auth');
const { audit } = require('../lib/audit');
const soar = require('../lib/soar');

router.get('/soar/playbooks/builtin', optionalAuth, (req, res, next) => {
  try {
    res.json(Object.values(soar.getBuiltinPlaybooks()));
  } catch (err) { next(err); }
});

router.get('/soar/playbooks/builtin/:name', optionalAuth, (req, res, next) => {
  try {
    const result = soar.getBuiltinPlaybook(req.params.name);
    if (!result) return res.status(404).json({ error: 'Playbook not found' });
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/soar/execute', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { playbookId, context } = req.body;
    if (!playbookId) return res.status(400).json({ error: 'playbookId is required' });
    const executionId = soar.startPlaybook(playbookId, context || {});
    audit('soar_executed', req, { playbookId, executionId });
    res.json({ executionId, status: 'started' });
  } catch (err) { next(err); }
});

router.post('/soar/stop/:executionId', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = soar.stopPlaybook(req.params.executionId);
    if (!result) return res.status(404).json({ error: 'Execution not found' });
    audit('soar_stopped', req, { executionId: req.params.executionId });
    res.json({ status: 'stopped' });
  } catch (err) { next(err); }
});

router.get('/soar/executions', authenticate, (req, res, next) => {
  try {
    const filters = {};
    if (req.query.status) filters.status = req.query.status;
    if (req.query.playbookId) filters.playbookId = req.query.playbookId;
    if (req.query.limit) filters.limit = parseInt(req.query.limit);
    res.json(soar.listExecutions(filters));
  } catch (err) { next(err); }
});

router.get('/soar/executions/:executionId', authenticate, (req, res, next) => {
  try {
    const result = soar.getPlaybookStatus(req.params.executionId);
    if (!result) return res.status(404).json({ error: 'Execution not found' });
    res.json(result);
  } catch (err) { next(err); }
});

router.delete('/soar/executions', authenticate, authorize('admin'), (req, res, next) => {
  try {
    soar.clearExecutions();
    audit('soar_executions_cleared', req);
    res.status(204).send();
  } catch (err) { next(err); }
});

module.exports = router;
