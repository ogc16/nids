const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const config = require('./config');
const { AuthError, ForbiddenError } = require('./errors');
const { audit } = require('./audit');

const USERS_FILE = path.join(config.dataDir, 'users.json');

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
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, config.jwtSecret, { expiresIn: config.jwtExpiresIn });
}

function verifyToken(token) {
  return jwt.verify(token, config.jwtSecret);
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

  users.push({
    id: 1,
    username: 'admin',
    password: hashPassword('admin'),
    role: 'admin',
    displayName: 'Administrator',
    email: 'admin@nids.local',
    createdAt: new Date().toISOString(),
    lastLogin: null
  });
  writeUsers(users);
  console.log('[AUTH] Default admin user created (admin:admin) — CHANGE IMMEDIATELY in production');
}

function loginRoute(req, res) {
  const { username, password } = req.body;
  const users = readUsers();
  const user = users.find(u => u.username === username);

  if (!user || !verifyPassword(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  user.lastLogin = new Date().toISOString();
  writeUsers(users);

  const token = generateToken(user);
  res.cookie(config.cookieName, token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: config.cookieMaxAge,
    path: '/'
  });
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, displayName: user.displayName, email: user.email }
  });
}

function meRoute(req, res) {
  const users = readUsers();
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, role: user.role, displayName: user.displayName, email: user.email, createdAt: user.createdAt, lastLogin: user.lastLogin });
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

  const maxId = users.reduce((m, u) => Math.max(m, u.id), 0);
  const user = {
    id: maxId + 1,
    username,
    password: hashPassword(password),
    role: role || 'analyst',
    displayName: displayName || username,
    email: email || '',
    createdAt: new Date().toISOString(),
    lastLogin: null
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
  if (password) users[idx].password = hashPassword(password);
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

module.exports = { authenticate, optionalAuth, authorize, ROLES, seedAdminUser, loginRoute, meRoute, listUsersRoute, createUserRoute, updateUserRoute, deleteUserRoute, readUsers };
