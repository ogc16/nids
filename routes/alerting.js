const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const alerting = require('../lib/alerting');

router.get('/alerting/config', authenticate, (req, res, next) => {
  try {
    res.json(alerting.getConfig());
  } catch (err) { next(err); }
});

router.put('/alerting/config', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const result = alerting.saveConfig(req.body);
    audit('alerting_config_updated', req);
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/alerting/test', authenticate, authorize('admin'), async (req, res, next) => {
  try {
    const { type = 'email' } = req.body || {};
    const config = alerting.getConfig();
    let result;
    if (type === 'email' && config.email.enabled) {
      result = await alerting.sendEmail({ to: config.email.to || 'test@example.com', subject: 'NIDS Alert Test', html: '<h1>Test Alert</h1><p>This is a test notification.</p>' });
    } else if (type === 'slack' && config.slack.enabled) {
      result = await alerting.sendSlack({ webhookUrl: config.slack.webhookUrl, text: 'NIDS Test Alert' });
    } else if (type === 'webhook' && config.webhook.enabled) {
      result = await alerting.sendWebhook({ url: config.webhook.url, method: config.webhook.method || 'POST', body: { test: true, message: 'NIDS Test Alert' } });
    }
    res.json(result || { success: false, error: `${type} not configured or disabled` });
  } catch (err) { next(err); }
});

module.exports = router;
