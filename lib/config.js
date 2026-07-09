const config = {
  port: 3000,
  host: '0.0.0.0',
  https: { port: 3443 },
  cookieName: 'nids_token',
  corsOrigin: '*',
  rateLimitWindowMs: 60000,
  rateLimitMax: 200,
  authRateLimitMax: 20,
  maxPageSize: 100,
  defaultPageSize: 25,
  version: '2.0.0',
  defaults: {},

  getAll() { return { ...this }; },
  set(key, value) { this[key] = value; },
};

module.exports = config;
