'use client';

import { useEffect, useState } from 'react';

export default function AlertingPage() {
  const [config, setConfig] = useState<any>({ email: {}, slack: {}, webhook: {} });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetch('/api/alerting/config').then(r => r.json()).then(setConfig).catch(() => {});
  }, []);

  async function handleSave() {
    setSaving(true);
    await fetch('/api/alerting/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    setSaving(false);
  }

  async function handleTest(type: string) {
    const res = await fetch('/api/alerting/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type }),
    });
    const data = await res.json();
    alert(data.success ? 'Test sent successfully!' : `Test failed: ${data.error}`);
  }

  function updateSection(section: string, field: string, value: any) {
    setConfig((prev: any) => ({ ...prev, [section]: { ...prev[section], [field]: value } }));
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Alerting Configuration</h2>
          <div className="subtitle">Configure email, Slack, and webhook notifications</div>
        </div>
        <button className="btn btn-primary" onClick={handleSave} disabled={saving}>{saving ? 'Saving...' : 'Save Config'}</button>
      </div>

      <div className="charts-row">
        <div className="card">
          <div className="card-header">
            <div className="card-title">Email</div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={config.email?.enabled || false} onChange={e => updateSection('email', 'enabled', e.target.checked)} />
              Enabled
            </label>
          </div>
          <div className="form-container">
            <div className="form-row">
              <div className="form-group"><label>SMTP Host</label><input className="form-control" value={config.email?.smtpHost || ''} onChange={e => updateSection('email', 'smtpHost', e.target.value)} /></div>
              <div className="form-group"><label>SMTP Port</label><input className="form-control" type="number" value={config.email?.smtpPort || 587} onChange={e => updateSection('email', 'smtpPort', parseInt(e.target.value))} /></div>
            </div>
            <div className="form-row">
              <div className="form-group"><label>Username</label><input className="form-control" value={config.email?.user || ''} onChange={e => updateSection('email', 'user', e.target.value)} /></div>
              <div className="form-group"><label>Password</label><input className="form-control" type="password" value={config.email?.pass || ''} onChange={e => updateSection('email', 'pass', e.target.value)} /></div>
            </div>
            <div className="form-group"><label>Send To</label><input className="form-control" value={config.email?.to || ''} onChange={e => updateSection('email', 'to', e.target.value)} /></div>
            <button className="btn btn-info btn-sm" onClick={() => handleTest('email')}>Test Email</button>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Slack</div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={config.slack?.enabled || false} onChange={e => updateSection('slack', 'enabled', e.target.checked)} />
              Enabled
            </label>
          </div>
          <div className="form-container">
            <div className="form-group"><label>Webhook URL</label><input className="form-control" value={config.slack?.webhookUrl || ''} onChange={e => updateSection('slack', 'webhookUrl', e.target.value)} placeholder="https://hooks.slack.com/services/..." /></div>
            <button className="btn btn-info btn-sm" onClick={() => handleTest('slack')}>Test Slack</button>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Webhook</div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
            <input type="checkbox" checked={config.webhook?.enabled || false} onChange={e => updateSection('webhook', 'enabled', e.target.checked)} />
            Enabled
          </label>
        </div>
        <div className="form-container">
          <div className="form-row">
            <div className="form-group"><label>URL</label><input className="form-control" value={config.webhook?.url || ''} onChange={e => updateSection('webhook', 'url', e.target.value)} /></div>
            <div className="form-group"><label>Method</label><select className="filter-select" value={config.webhook?.method || 'POST'} onChange={e => updateSection('webhook', 'method', e.target.value)}><option>GET</option><option>POST</option><option>PUT</option></select></div>
          </div>
          <button className="btn btn-info btn-sm" onClick={() => handleTest('webhook')}>Test Webhook</button>
        </div>
      </div>
    </>
  );
}
