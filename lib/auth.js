const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');
const { AuthError, ForbiddenError } = require('./errors');
const { audit } = require('./audit');

const USERS_FILE = path.join(config.dataDir, 'users.json');
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;
const loginAttempts = new Map();

function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

function hashPassword(password) {
  return bcrypt.hashSync(password, config.bcryptRounds);
}

function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role, mustChangePwd: !!user.mustChangePwd }, config.jwtSecret, { expiresIn: config.jwtExpiresIn });
}

function verifyToken(token) {
  return jwt.verify(token, config.jwtSecret);
}

function checkPasswordStrength(password) {
  if (!password || password.length < 12) return 'Password must be at least 12 characters';
  if (!/[A-Z]/.test(password)) return 'Password must contain an uppercase letter';
  if (!/[a-z]/.test(password)) return 'Password must contain a lowercase letter';
  if (!/[0-9]/.test(password)) return 'Password must contain a digit';
  if (!/[^A-Za-z0-9]/.test(password)) return 'Password must contain a special character';
  return null;
}

function isLockedOut(username) {
  const record = loginAttempts.get(username);
  if (!record) return false;
  if (Date.now() - record.windowStart > LOCKOUT_WINDOW_MS) {
    loginAttempts.delete(username);
    return false;
  }
  return record.count >= LOCKOUT_THRESHOLD;
}

function recordFailedAttempt(username) {
  const record = loginAttempts.get(username) || { count: 0, windowStart: Date.now() };
  if (Date.now() - record.windowStart > LOCKOUT_WINDOW_MS) {
    record.count = 1;
    record.windowStart = Date.now();
  } else {
    record.count++;
  }
  loginAttempts.set(username, record);
}

function clearLockout(username) {
  loginAttempts.delete(username);
}

function authenticate(req, _res, next) {
  let token;
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    token = header.split(' ')[1];
  } else if (req.cookies && req.cookies[config.cookieName]) {
    token = req.cookies[config.cookieName];
  }
  if (!token) return next(new AuthError());

  try {
    req.user = verifyToken(token);
    next();
  } catch {
    next(new AuthError('Invalid or expired token'));
  }
}

function optionalAuth(req, _res, next) {
  let token;
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    token = header.split(' ')[1];
  } else if (req.cookies && req.cookies[config.cookieName]) {
    token = req.cookies[config.cookieName];
  }
  if (token) {
    try { req.user = verifyToken(token); } catch { req.user = null; }
  }
  next();
}

function authorize(...roles) {
  return (req, _res, next) => {
    if (!req.user) return next(new AuthError());
    if (roles.length > 0 && !roles.includes(req.user.role)) {
      audit('authorization_denied', req, { requiredRole: roles, userRole: req.user.role });
      return next(new ForbiddenError(`Requires one of roles: ${roles.join(', ')}`));
    }
    next();
  };
}

const ROLES = {
  admin: { weight: 100, label: 'Administrator' },
  analyst: { weight: 50, label: 'SOC Analyst' },
  viewer: { weight: 10, label: 'Viewer' }
};

function seedAdminUser() {
  const users = readUsers();
  if (users.some(u => u.username === 'admin')) return;

  const initialPassword = crypto.randomBytes(6).toString('hex');
  users.push({
    id: 1,
    username: 'admin',
    password: hashPassword(initialPassword),
    role: 'admin',
    displayName: 'Administrator',
    email: 'admin@nids.local',
    createdAt: new Date().toISOString(),
    lastLogin: null,
    mustChangePwd: true
  });
  writeUsers(users);
  console.log(`[AUTH] Default admin user created with password: ${initialPassword}`);
  console.log(`[AUTH] CHANGE THIS PASSWORD ON FIRST LOGIN`);
}

function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

function csrfProtection(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  const expected = req.cookies?.['csrf-token'];
  if (!expected || !token || token !== expected) {
    return next(new AuthError('Invalid CSRF token'));
  }
  next();
}

function loginRoute(req, res) {
  const { username, password } = req.body;

  if (isLockedOut(username)) {
    return res.status(429).json({ error: 'Account temporarily locked. Try again in 15 minutes.' });
  }

  const users = readUsers();
  const user = users.find(u => u.username === username);

  if (!user || !verifyPassword(password, user.password)) {
    recordFailedAttempt(username);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  clearLockout(username);

  if (user.mustChangePwd) {
    const tempToken = generateToken(user);
    return res.json({
      mustChangePwd: true,
      tempToken,
      user: { id: user.id, username: user.username, role: user.role }
    });
  }

  user.lastLogin = new Date().toISOString();
  writeUsers(users);

  const token = generateToken(user);
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  res.cookie(config.cookieName, token, {
    httpOnly: true,
    secure: isSecure,
    sameSite: 'strict',
    maxAge: config.cookieMaxAge,
    path: '/'
  });
  const csrfToken = generateCsrfToken();
  res.cookie('csrf-token', csrfToken, {
    httpOnly: false,
    secure: isSecure,
    sameSite: 'strict',
    maxAge: config.cookieMaxAge,
    path: '/'
  });
  res.json({
    token,
    csrfToken,
    user: { id: user.id, username: user.username, role: user.role, displayName: user.displayName, email: user.email }
  });
}

function changePasswordRoute(req, res) {
  const { currentPassword, newPassword } = req.body;
  const users = readUsers();
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!verifyPassword(currentPassword, user.password)) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  const strengthError = checkPasswordStrength(newPassword);
  if (strengthError) return res.status(400).json({ error: strengthError });
  if (currentPassword === newPassword) return res.status(400).json({ error: 'New password must differ from current password' });
  user.password = hashPassword(newPassword);
  user.mustChangePwd = false;
  writeUsers(users);
  res.json({ status: 'ok', message: 'Password changed successfully' });
}

function meRoute(req, res) {
  const users = readUsers();
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, role: user.role, displayName: user.displayName, email: user.email, createdAt: user.createdAt, lastLogin: user.lastLogin, mustChangePwd: user.mustChangePwd || false });
}

function listUsersRoute(req, res) {
  const users = readUsers();
  res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role, displayName: u.displayName, email: u.email, createdAt: u.createdAt, lastLogin: u.lastLogin })));
}

function createUserRoute(req, res, next) {
  const { username, password, role, displayName, email } = req.body;
  const users = readUsers();

  if (users.some(u => u.username === username)) {
    return next(Object.assign(new Error('Username already exists'), { statusCode: 409, isOperational: true }));
  }

  const strengthError = checkPasswordStrength(password);
  if (strengthError) return next(Object.assign(new Error(strengthError), { statusCode: 400, isOperational: true }));

  const maxId = users.reduce((m, u) => Math.max(m, u.id), 0);
  const user = {
    id: maxId + 1,
    username,
    password: hashPassword(password),
    role: role || 'analyst',
    displayName: displayName || username,
    email: email || '',
    createdAt: new Date().toISOString(),
    lastLogin: null,
    mustChangePwd: true
  };
  users.push(user);
  writeUsers(users);

  res.status(201).json({ id: user.id, username: user.username, role: user.role, displayName: user.displayName, email: user.email });
}

function updateUserRoute(req, res) {
  const { id } = req.params;
  const users = readUsers();
  const idx = users.findIndex(u => u.id === parseInt(id));
  if (idx === -1) return res.status(404).json({ error: 'User not found' });

  const { displayName, role, email, password } = req.body;
  if (displayName !== undefined) users[idx].displayName = displayName;
  if (role !== undefined) users[idx].role = role;
  if (email !== undefined) users[idx].email = email;
  if (password) {
    const strengthError = checkPasswordStrength(password);
    if (strengthError) return res.status(400).json({ error: strengthError });
    users[idx].password = hashPassword(password);
    users[idx].mustChangePwd = false;
  }
  writeUsers(users);

  res.json({ id: users[idx].id, username: users[idx].username, role: users[idx].role, displayName: users[idx].displayName, email: users[idx].email });
}

function deleteUserRoute(req, res) {
  const { id } = req.params;
  const users = readUsers();
  const idx = users.findIndex(u => u.id === parseInt(id));
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  if (users[idx].username === 'admin') return res.status(403).json({ error: 'Cannot delete admin user' });

  users.splice(idx, 1);
  writeUsers(users);
  res.status(204).send();
}

module.exports = { authenticate, optionalAuth, authorize, ROLES, seedAdminUser, loginRoute, changePasswordRoute, meRoute, listUsersRoute, createUserRoute, updateUserRoute, deleteUserRoute, readUsers, csrfProtection, checkPasswordStrength };
