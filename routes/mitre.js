const express = require('express');
const router = express.Router();
const { authenticate, authorize, optionalAuth } = require('../lib/auth');
const { audit } = require('../lib/audit');
const mitre = require('../lib/mitre');

router.get('/mitre/tactics', optionalAuth, (req, res, next) => {
  try {
    res.json(mitre.getTactics());
  } catch (err) { next(err); }
});

router.get('/mitre/techniques', optionalAuth, (req, res, next) => {
  try {
    const { tactic, search } = req.query;
    let techniques = mitre.getTechniques();
    if (tactic) techniques = techniques.filter(t => t.tactic === tactic);
    if (search) techniques = techniques.filter(t => t.name.toLowerCase().includes(search.toLowerCase()) || t.id.toLowerCase().includes(search.toLowerCase()));
    res.json(techniques);
  } catch (err) { next(err); }
});

router.get('/mitre/coverage', authenticate, (req, res, next) => {
  try {
    res.json(mitre.getCoverage());
  } catch (err) { next(err); }
});

router.get('/mitre/matrix', optionalAuth, (req, res, next) => {
  try {
    res.json(mitre.getMatrix());
  } catch (err) { next(err); }
});

router.post('/mitre/analyze', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { type, data } = req.body;
    if (!type || !data) return res.status(400).json({ error: 'Type and data are required' });
    const result = mitre.analyze(type, data);
    audit('mitre_analysis', req, { type });
    res.json(result);
  } catch (err) { next(err); }
});

module.exports = router;
