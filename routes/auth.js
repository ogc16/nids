const express = require('express');
const router = express.Router();
const { authenticate, authorize, loginRoute, changePasswordRoute, meRoute, listUsersRoute, createUserRoute, updateUserRoute, deleteUserRoute } = require('../lib/auth');
const { validate, schemas } = require('../lib/validate');
const { audit } = require('../lib/audit');
const config = require('../lib/config');

router.post('/login', validate(schemas.login), (req, res, next) => {
  try {
    audit('login_attempt', req, { username: req.body.username });
    loginRoute(req, res);
  } catch (err) { next(err); }
});

router.get('/me', authenticate, meRoute);

router.get('/users', authenticate, authorize('admin'), listUsersRoute);
router.post('/users', authenticate, authorize('admin'), validate(schemas.login), createUserRoute);
router.put('/users/:id', authenticate, authorize('admin'), updateUserRoute);
router.delete('/users/:id', authenticate, authorize('admin'), deleteUserRoute);

router.post('/change-password', authenticate, (req, res, next) => {
  try { changePasswordRoute(req, res); } catch (err) { next(err); }
});

router.post('/logout', authenticate, (req, res) => {
  res.clearCookie(config.cookieName, { path: '/' });
  res.clearCookie('csrf-token', { path: '/' });
  res.json({ status: 'ok', message: 'Logged out' });
});

module.exports = router;
