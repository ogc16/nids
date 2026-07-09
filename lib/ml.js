let models = [];

function listModels() { return models; }

function createModel(body) {
  const model = { id: `model_${Date.now()}`, name: body.name || 'model', type: body.type || 'anomaly', status: 'created', createdAt: new Date().toISOString() };
  models.push(model);
  return model;
}

function trainModel(id, body) {
  const model = models.find((m) => m.id === id);
  if (model) model.status = 'trained';
  return { id, status: 'trained', accuracy: 0.94 };
}

function predict(id, body) {
  return { id, prediction: 'normal', confidence: 0.87, features: body };
}

function analyze(data, modelType) {
  return { modelType, anomalies: [{ timestamp: Date.now(), severity: 'medium', description: 'Anomalous traffic pattern' }] };
}

function getAnomalies() {
  return [{ id: 'anomaly_1', timestamp: Date.now(), severity: 'high', description: 'Unusual outbound traffic', source: '10.0.0.45' }];
}

function getFeatureImportance() {
  return [{ feature: 'packet_size', importance: 0.32 }, { feature: 'protocol', importance: 0.28 }, { feature: 'payload_pattern', importance: 0.25 }, { feature: 'port', importance: 0.15 }];
}

module.exports = { listModels, createModel, trainModel, predict, analyze, getAnomalies, getFeatureImportance };
