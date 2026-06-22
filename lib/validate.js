const { ValidationError } = require('./errors');

function validate(schema) {
  return (req, _res, next) => {
    const errors = [];
    const data = req.body || {};

    for (const [field, rules] of Object.entries(schema)) {
      const value = data[field];

      if (rules.required && (value === undefined || value === null || value === '')) {
        errors.push(`${field} is required`);
        continue;
      }

      if (value === undefined || value === null || value === '') continue;

      if (rules.type === 'string' && typeof value !== 'string') {
        errors.push(`${field} must be a string`);
      }
      if (rules.type === 'number' && (typeof value !== 'number' || isNaN(value))) {
        errors.push(`${field} must be a number`);
      }
      if (rules.type === 'array' && !Array.isArray(value)) {
        errors.push(`${field} must be an array`);
      }
      if (rules.type === 'boolean' && typeof value !== 'boolean') {
        errors.push(`${field} must be a boolean`);
      }
      if (rules.minLength && typeof value === 'string' && value.length < rules.minLength) {
        errors.push(`${field} must be at least ${rules.minLength} characters`);
      }
      if (rules.maxLength && typeof value === 'string' && value.length > rules.maxLength) {
        errors.push(`${field} must be at most ${rules.maxLength} characters`);
      }
      if (rules.min !== undefined && typeof value === 'number' && value < rules.min) {
        errors.push(`${field} must be at least ${rules.min}`);
      }
      if (rules.max !== undefined && typeof value === 'number' && value > rules.max) {
        errors.push(`${field} must be at most ${rules.max}`);
      }
      if (rules.oneOf && !rules.oneOf.includes(value)) {
        errors.push(`${field} must be one of: ${rules.oneOf.join(', ')}`);
      }
      if (rules.pattern && typeof value === 'string' && !rules.pattern.test(value)) {
        errors.push(`${field} format is invalid`);
      }
    }

    if (errors.length > 0) {
      return next(new ValidationError('Validation failed', errors));
    }
    next();
  };
}

const schemas = {
  login: {
    username: { required: true, type: 'string', minLength: 2, maxLength: 100 },
    password: { required: true, type: 'string', minLength: 1 }
  },
  createIncident: {
    title: { required: true, type: 'string', minLength: 2, maxLength: 500 },
    severity: { required: true, type: 'string', oneOf: ['Critical', 'High', 'Medium', 'Low'] },
    status: { required: true, type: 'string', oneOf: ['New', 'Investigating', 'Resolved', 'Closed'] },
    attackType: { required: true, type: 'string', minLength: 2 },
    sourceIp: { required: true, type: 'string' },
    assignee: { type: 'string' },
    cvssScore: { type: 'number', min: 0, max: 10 },
    csfFunction: { type: 'string', oneOf: ['', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC'] }
  },
  createRule: {
    name: { required: true, type: 'string', minLength: 2, maxLength: 200 },
    status: { required: true, type: 'string', oneOf: ['Active', 'In Development', 'Deprecated'] },
    priority: { required: true, type: 'string', oneOf: ['Critical', 'High', 'Medium', 'Low'] },
    csfFunction: { type: 'string', oneOf: ['', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC'] }
  },
  createAsset: {
    assetName: { required: true, type: 'string', minLength: 2, maxLength: 200 },
    ipRange: { required: true, type: 'string' },
    type: { required: true, type: 'string' },
    riskLevel: { required: true, type: 'string', oneOf: ['Critical', 'High', 'Medium', 'Low'] },
    monitoringStatus: { required: true, type: 'string', oneOf: ['Online', 'Degraded', 'Offline'] },
    owner: { required: true, type: 'string' }
  },
  createPolicy: {
    name: { required: true, type: 'string', minLength: 2, maxLength: 200 },
    category: { required: true, type: 'string' },
    status: { required: true, type: 'string', oneOf: ['Active', 'Draft', 'Archived'] },
    csfFunction: { type: 'string', oneOf: ['', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC'] }
  },
  createStandard: {
    name: { required: true, type: 'string', minLength: 2, maxLength: 200 },
    category: { required: true, type: 'string' },
    status: { required: true, type: 'string', oneOf: ['Active', 'Draft', 'Archived'] },
    csfFunction: { type: 'string', oneOf: ['', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC'] }
  }
};

module.exports = { validate, schemas };
