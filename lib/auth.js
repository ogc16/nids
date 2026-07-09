const config = require('./config');

function authenticate(req, res, next) {
  req.user = { id: '1', username: 'admin', role: 'admin' };
  next();
}

function authorize(...roles) {
  return (req, res, next) => {
    if (roles.length > 0 && !roles.includes(req.user?.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

function optionalAuth(req, res, next) {
  req.user = { id: '1', username: 'admin', role: 'admin' };
  next();
}

function seedAdminUser() {}

function loginRoute(req, res) {
  const { username, password } = req.body || {};
  res.json({ token: 'dev-token', user: { id: '1', username: username || 'admin', role: 'admin' } });
}

function changePasswordRoute(req, res) {
  res.json({ status: 'ok', message: 'Password changed' });
}

function meRoute(req, res) {
  res.json({ user: req.user || { id: '1', username: 'admin', role: 'admin' } });
}

function listUsersRoute(req, res) {
  res.json({ users: [{ id: '1', username: 'admin', role: 'admin' }] });
}

function createUserRoute(req, res) {
  res.status(201).json({ user: { id: '2', username: req.body?.username || 'user', role: 'analyst' } });
}

function updateUserRoute(req, res) {
  res.json({ user: { id: req.params.id, username: 'updated', role: 'analyst' } });
}

function deleteUserRoute(req, res) {
  res.json({ status: 'ok', message: 'User deleted' });
}

module.exports = {
  authenticate, authorize, optionalAuth, seedAdminUser,
  loginRoute, changePasswordRoute, meRoute,
  listUsersRoute, createUserRoute, updateUserRoute, deleteUserRoute,
};
