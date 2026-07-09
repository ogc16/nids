let config = {
  email: { enabled: false, smtpHost: '', smtpPort: 587, username: '', password: '', from: 'alerts@nids.local' },
  slack: { enabled: false, webhookUrl: '' },
  webhook: { enabled: false, url: '', method: 'POST' },
};

function getConfig() { return config; }

function saveConfig(body) {
  config = { ...config, ...body };
  return config;
}

async function sendEmail({ to, subject, html }) {
  console.log(`[Alerting] Email to ${to}: ${subject}`);
  return { success: true, messageId: `email_${Date.now()}` };
}

async function sendSlack({ webhookUrl, text }) {
  console.log(`[Alerting] Slack to ${webhookUrl}: ${text}`);
  return { success: true };
}

async function sendWebhook({ url, method, body }) {
  console.log(`[Alerting] Webhook ${method} ${url}`);
  return { success: true };
}

module.exports = { getConfig, saveConfig, sendEmail, sendSlack, sendWebhook };
