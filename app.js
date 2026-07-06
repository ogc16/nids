const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const path = require('path');
const multer = require('multer');

const config = require('./lib/config');
const { authenticate, authorize, seedAdminUser } = require('./lib/auth');
const { errorHandler, notFoundHandler } = require('./lib/errors');
const db = require('./lib/db');

const app = express();

// Security middleware
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: config.corsOrigin, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Block direct .html access
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) return res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
  next();
});

// Serve static files; auto-append .html for clean URLs
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// Global rate limiting
app.use(rateLimit({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax * 5, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests' } }));
app.use('/api/', rateLimit({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests' } }));
app.use('/api/auth/', rateLimit({ windowMs: config.rateLimitWindowMs, max: config.authRateLimitMax, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many auth attempts' } }));

// CSRF protection for state-changing requests
app.use('/api/', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.path.startsWith('/auth/login') || req.path.startsWith('/auth/change-password')) return next();
  if (!req.cookies?.[config.cookieName]) return next();
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  const expected = req.cookies?.['csrf-token'];
  if (!expected || !token || token !== expected) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
});

// Mount all API routes
const { router } = require('./routes');
app.use('/api', router);

// DB stats
app.get('/api/db/stats', authenticate, authorize('admin'), (req, res) => {
  res.json(db.getStats());
});

// Error handling
app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
