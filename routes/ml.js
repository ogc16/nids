const express = require('express');
const router = express.Router();
const { authenticate, authorize, optionalAuth } = require('../lib/auth');
const { audit } = require('../lib/audit');
const ml = require('../lib/ml');

router.get('/ml/models', optionalAuth, (req, res, next) => {
  try {
    res.json(ml.listModels());
  } catch (err) { next(err); }
});

router.post('/ml/models', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = ml.createModel(req.body);
    audit('ml_model_created', req, { name: result.name });
    res.status(201).json(result);
  } catch (err) { next(err); }
});

router.post('/ml/models/:id/train', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = ml.trainModel(req.params.id, req.body);
    audit('ml_model_trained', req, { id: req.params.id });
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/ml/models/:id/predict', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const result = ml.predict(req.params.id, req.body);
    audit('ml_prediction', req, { id: req.params.id });
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/ml/analyze', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { data, modelType = 'anomaly' } = req.body;
    if (!data) return res.status(400).json({ error: 'Data is required' });
    const result = ml.analyze(data, modelType);
    audit('ml_analysis', req, { modelType });
    res.json(result);
  } catch (err) { next(err); }
});

router.get('/ml/anomalies', optionalAuth, (req, res, next) => {
  try {
    res.json(ml.getAnomalies());
  } catch (err) { next(err); }
});

router.get('/ml/feature-importance', optionalAuth, (req, res, next) => {
  try {
    res.json(ml.getFeatureImportance());
  } catch (err) { next(err); }
});

module.exports = router;
