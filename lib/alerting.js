const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const config = require('./config');

const CONFIG_FILE = path.join(config.dataDir, 'alerting-config.json');

const DEFAULT_CONFIG = {
  email: {
    enabled: false,
    smtp: {
      host: process.env.SMTP_HOST || '',
      port: parseInt(process.env.SMTP_PORT, 10) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER || '',
        pass: process.env.SMTP_PASS || ''
      }
    },
    from: process.env.SMTP_FROM || ''
  },
  slack: {
    enabled: false,
    webhookUrl: process.env.SLACK_WEBHOOK_URL || ''
  },
  webhook: {
    enabled: false,
    url: process.env.WEBHOOK_URL || '',
    method: 'POST',
    headers: {}
  },
  rules: []
};

function getConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
      return mergeConfig(JSON.parse(raw));
    }
  } catch (err) {
    console.error('[Alerting] Error reading config:', err.message);
  }
  return { ...DEFAULT_CONFIG, rules: [...DEFAULT_CONFIG.rules] };
}

function mergeConfig(cfg) {
  return {
    email: { ...DEFAULT_CONFIG.email, ...cfg.email, smtp: { ...DEFAULT_CONFIG.email.smtp, ...(cfg.email || {}).smtp, auth: { ...DEFAULT_CONFIG.email.smtp.auth, ...((cfg.email || {}).smtp || {}).auth } } },
    slack: { ...DEFAULT_CONFIG.slack, ...cfg.slack },
    webhook: { ...DEFAULT_CONFIG.webhook, ...cfg.webhook, headers: { ...DEFAULT_CONFIG.webhook.headers, ...(cfg.webhook || {}).headers } },
    rules: Array.isArray(cfg.rules) ? cfg.rules : []
  };
}

function saveConfig(cfg) {
  try {
    const dir = path.dirname(CONFIG_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
    return { success: true };
  } catch (err) {
    console.error('[Alerting] Error saving config:', err.message);
    return { success: false, error: err.message };
  }
}

async function sendEmail({ to, subject, html }) {
  try {
    const cfg = getConfig();
    if (!cfg.email.enabled) return { success: false, error: 'Email alerts are disabled' };

    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
      host: cfg.email.smtp.host,
      port: cfg.email.smtp.port,
      secure: cfg.email.smtp.secure,
      auth: {
        user: cfg.email.smtp.auth.user,
        pass: cfg.email.smtp.auth.pass
      }
    });

    await transporter.sendMail({
      from: cfg.email.from || cfg.email.smtp.auth.user,
      to,
      subject,
      html
    });

    console.log(`[Alerting] Email sent to ${to}: ${subject}`);
    return { success: true };
  } catch (err) {
    console.error('[Alerting] Email error:', err.message);
    return { success: false, error: err.message };
  }
}

async function sendSlack({ webhookUrl, text, attachments }) {
  try {
    const cfg = getConfig();
    const url = webhookUrl || cfg.slack.webhookUrl;
    if (!url) return { success: false, error: 'No Slack webhook URL provided' };

    if (!cfg.slack.enabled && !webhookUrl) return { success: false, error: 'Slack alerts are disabled' };

    const body = { text };
    if (attachments) body.attachments = attachments;

    const result = await sendWebhook({ url, method: 'POST', headers: { 'Content-Type': 'application/json' }, body });

    if (result.success) console.log('[Alerting] Slack notification sent');
    return result;
  } catch (err) {
    console.error('[Alerting] Slack error:', err.message);
    return { success: false, error: err.message };
  }
}

async function sendWebhook({ url, method, headers, body }) {
  try {
    if (!url) return { success: false, error: 'No webhook URL provided' };

    const m = (method || 'POST').toUpperCase();
    if (m !== 'POST' && m !== 'PUT') return { success: false, error: 'Method must be POST or PUT' };

    const payload = JSON.stringify(body || {});
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: m,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        ...headers
      }
    };

    return new Promise((resolve) => {
      const lib = isHttps ? https : http;
      const req = lib.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ success: true, statusCode: res.statusCode, data });
          } else {
            resolve({ success: false, statusCode: res.statusCode, error: data || `HTTP ${res.statusCode}` });
          }
        });
      });

      req.on('error', (err) => {
        resolve({ success: false, error: err.message });
      });

      req.write(payload);
      req.end();
    });
  } catch (err) {
    return { success: false, error: err.message };
  }
}

function evaluateCondition(condition, data) {
  const value = data[condition.field];
  switch (condition.operator) {
    case 'eq': return value === condition.value;
    case 'neq': return value !== condition.value;
    case 'gt': return value > condition.value;
    case 'gte': return value >= condition.value;
    case 'lt': return value < condition.value;
    case 'lte': return value <= condition.value;
    case 'contains': return String(value).includes(String(condition.value));
    case 'startsWith': return String(value).startsWith(String(condition.value));
    case 'endsWith': return String(value).endsWith(String(condition.value));
    case 'regex': return new RegExp(condition.value).test(String(value));
    case 'in': return Array.isArray(condition.value) && condition.value.includes(value);
    case 'notIn': return Array.isArray(condition.value) && !condition.value.includes(value);
    default: return false;
  }
}

function checkRules(event, data) {
  const cfg = getConfig();
  const triggered = [];

  for (const rule of cfg.rules) {
    if (!rule.enabled) continue;
    if (rule.eventType !== event) continue;

    const allMatch = rule.conditions.every((cond) => evaluateCondition(cond, data));
    if (!allMatch) continue;

    triggered.push(rule);
  }

  return triggered;
}

async function executeAction(action, data) {
  switch (action.type) {
    case 'email':
      return sendEmail({
        to: action.config.to,
        subject: action.config.subject || 'NIDS Alert',
        html: action.config.html || formatAlertHtml(data)
      });
    case 'slack':
      return sendSlack({
        webhookUrl: action.config.webhookUrl,
        text: action.config.text || formatAlertText(data),
        attachments: action.config.attachments
      });
    case 'webhook':
      return sendWebhook({
        url: action.config.url,
        method: action.config.method,
        headers: action.config.headers,
        body: action.config.body || data
      });
    default:
      return { success: false, error: `Unknown action type: ${action.type}` };
  }
}

function formatAlertHtml(data) {
  let html = '<h2>NIDS Alert</h2><table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse">';
  for (const [key, val] of Object.entries(data)) {
    html += `<tr><td><strong>${key}</strong></td><td>${typeof val === 'object' ? JSON.stringify(val) : val}</td></tr>`;
  }
  return html + '</table>';
}

function formatAlertText(data) {
  let text = '*NIDS Alert*\n';
  for (const [key, val] of Object.entries(data)) {
    text += `*${key}:* ${typeof val === 'object' ? JSON.stringify(val) : val}\n`;
  }
  return text;
}

async function notify(event, data) {
  const results = [];
  const matchedRules = checkRules(event, data);

  for (const rule of matchedRules) {
    for (const action of rule.actions) {
      const result = await executeAction(action, data);
      result.ruleId = rule.id;
      result.ruleName = rule.name;
      result.actionType = action.type;
      result.event = event;
      results.push(result);
    }
  }

  if (results.length > 0) {
    console.log(`[Alerting] Processed event "${event}" — ${results.filter(r => r.success).length}/${results.length} actions succeeded`);
  }

  return results;
}

module.exports = { getConfig, saveConfig, sendEmail, sendSlack, sendWebhook, checkRules, notify };
