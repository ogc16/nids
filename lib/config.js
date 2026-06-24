const path = require('path');

const config = {
  port: parseInt(process.env.PORT, 10) || 3000,
  host: process.env.HOST || '0.0.0.0',
  jwtSecret: process.env.JWT_SECRET || 'nids-enterprise-secret-change-in-production',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '8h',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
  dataDir: path.resolve(process.env.DATA_DIR || path.join(__dirname, '..', 'data')),
  logLevel: process.env.LOG_LEVEL || 'info',
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60000,
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX, 10) || 100,
  authRateLimitMax: parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 10,
  corsOrigin: process.env.CORS_ORIGIN || '*',
  defaultPageSize: parseInt(process.env.DEFAULT_PAGE_SIZE, 10) || 50,
  maxPageSize: parseInt(process.env.MAX_PAGE_SIZE, 10) || 500,
  cookieName: 'nids_token',
  cookieMaxAge: 8 * 3600 * 1000, // 8 hours (matches jwtExpiresIn)
  https: {
    enabled: process.env.HTTPS_ENABLED === 'true',
    port: parseInt(process.env.HTTPS_PORT, 10) || 3443,
    certPath: process.env.HTTPS_CERT_PATH || path.join(__dirname, '..', 'certs', 'cert.pem'),
    keyPath: process.env.HTTPS_KEY_PATH || path.join(__dirname, '..', 'certs', 'key.pem')
  }
};

module.exports = config;
