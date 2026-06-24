const path = require('path');
const crypto = require('crypto');

const jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
const corsOrigin = process.env.CORS_ORIGIN;
if (!corsOrigin && process.env.NODE_ENV === 'production') {
  console.warn('[CONFIG] WARNING: CORS_ORIGIN not set. Set it to your SOC domain in production.');
}
const csrfSecret = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');

const config = {
  port: parseInt(process.env.PORT, 10) || 3000,
  host: process.env.HOST || '0.0.0.0',
  jwtSecret,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '8h',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
  dataDir: path.resolve(process.env.DATA_DIR || path.join(process.cwd(), 'data')),
  logLevel: process.env.LOG_LEVEL || 'info',
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60000,
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX, 10) || 100,
  authRateLimitMax: parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 10,
  corsOrigin: corsOrigin || (process.env.NODE_ENV === 'production' ? 'http://localhost:3000' : '*'),
  defaultPageSize: parseInt(process.env.DEFAULT_PAGE_SIZE, 10) || 50,
  maxPageSize: parseInt(process.env.MAX_PAGE_SIZE, 10) || 500,
  cookieName: 'nids_token',
  cookieMaxAge: 8 * 3600 * 1000,
  csrfSecret,
  https: {
    enabled: process.env.HTTPS_ENABLED !== 'false',
    port: parseInt(process.env.HTTPS_PORT, 10) || 3443,
    certPath: process.env.HTTPS_CERT_PATH || path.join(process.cwd(), 'certs', 'cert.pem'),
    keyPath: process.env.HTTPS_KEY_PATH || path.join(process.cwd(), 'certs', 'key.pem')
  }
};

module.exports = config;
