const express = require('express');
const router = express.Router();
const { authenticate, authorize, optionalAuth } = require('../lib/auth');
const { audit } = require('../lib/audit');
const compliance = require('../lib/compliance');

router.get('/compliance/frameworks', optionalAuth, (req, res, next) => {
  try {
    const frameworks = ['pci-dss', 'hipaa', 'gdpr'];
    const result = frameworks.map(f => ({ framework: f, ...compliance.getComplianceStatus(f) }));
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/compliance/dashboard', authenticate, (req, res, next) => {
  try {
    res.json(compliance.getComplianceDashboard());
  } catch (err) { next(err); }
});

router.get('/compliance/recommendations', authenticate, (req, res, next) => {
  try {
    const frameworks = ['pci-dss', 'hipaa', 'gdpr'];
    const result = {};
    frameworks.forEach(f => { result[f] = compliance.generateRemediationPlan(f); });
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/compliance/evidence/:framework/:controlId', authenticate, (req, res, next) => {
  try {
    res.json(compliance.collectEvidence(req.params.framework, req.params.controlId));
  } catch (err) { next(err); }
});

router.get('/compliance/:framework', optionalAuth, (req, res, next) => {
  try {
    const data = compliance[req.params.framework.replace(/-/g, '') + 'Data'] || compliance.getComplianceStatus(req.params.framework);
    res.json(data);
  } catch (err) { next(err); }
});

router.get('/compliance/:framework/controls', optionalAuth, (req, res, next) => {
  try {
    const { assetType } = req.query;
    if (assetType) {
      res.json(compliance.getApplicableControls(assetType));
    } else {
      const frameworks = ['pci-dss', 'hipaa', 'gdpr'];
      const results = {};
      frameworks.forEach(f => { results[f] = compliance.getApplicableControls('all'); });
      res.json(results);
    }
  } catch (err) { next(err); }
});

router.get('/compliance/:framework/report', authenticate, (req, res, next) => {
  try {
    res.json(compliance.generateReport(req.params.framework, req.query));
  } catch (err) { next(err); }
});

module.exports = router;
