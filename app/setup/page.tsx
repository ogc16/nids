'use client';

import { useEffect, useState } from 'react';

export default function SetupPage() {
  const [settings, setSettings] = useState({ dashboardRefresh: 30, monitoringRefresh: 10, autoSimulate: 'off', maxTrafficDisplay: 100 });
  const [profile, setProfile] = useState({ operatorName: '', operatorRole: 'SOC Analyst', operatorTeam: '' });
  const [saving, setSaving] = useState(false);
  const [seeding, setSeeding] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetch('/api/setup/settings').then(r => r.json()).then(setSettings).catch(() => {});
    fetch('/api/setup/profile').then(r => r.json()).then(setProfile).catch(() => {});
  }, []);

  async function saveSettings() {
    setSaving(true);
    await fetch('/api/setup/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings) });
    setSaving(false);
    setMessage('Settings saved');
    setTimeout(() => setMessage(''), 2000);
  }

  async function saveProfile() {
    setSaving(true);
    await fetch('/api/setup/profile', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(profile) });
    setSaving(false);
    setMessage('Profile saved');
    setTimeout(() => setMessage(''), 2000);
  }

  async function handleSeed() {
    setSeeding(true);
    const res = await fetch('/api/setup/seed', { method: 'POST' });
    const data = await res.json();
    setMessage(data.message || 'Seed data loaded');
    setSeeding(false);
    setTimeout(() => setMessage(''), 3000);
  }

  async function handleReset() {
    if (!confirm('This will delete ALL data. Are you sure?')) return;
    setResetting(true);
    await fetch('/api/setup/reset', { method: 'POST' });
    setMessage('All data reset');
    setResetting(false);
    setTimeout(() => setMessage(''), 3000);
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Setup</h2>
          <div className="subtitle">System configuration, operator profile, and data management</div>
        </div>
      </div>

      {message && <div className="toast toast-success" style={{ position: 'static', marginBottom: 16, animation: 'none' }}>{message}</div>}

      <div className="charts-row">
        <div className="card">
          <div className="card-header"><div className="card-title">System Settings</div></div>
          <div className="form-container">
            <div className="form-group"><label>Dashboard Refresh (seconds)</label><input className="form-control" type="number" value={settings.dashboardRefresh} onChange={e => setSettings(p => ({ ...p, dashboardRefresh: parseInt(e.target.value) }))} /></div>
            <div className="form-group"><label>Monitoring Refresh (seconds)</label><input className="form-control" type="number" value={settings.monitoringRefresh} onChange={e => setSettings(p => ({ ...p, monitoringRefresh: parseInt(e.target.value) }))} /></div>
            <div className="form-group"><label>Auto Simulate</label><select className="filter-select" value={settings.autoSimulate} onChange={e => setSettings(p => ({ ...p, autoSimulate: e.target.value }))}><option value="off">Off</option><option value="on">On</option></select></div>
            <div className="form-group"><label>Max Traffic Display</label><input className="form-control" type="number" value={settings.maxTrafficDisplay} onChange={e => setSettings(p => ({ ...p, maxTrafficDisplay: parseInt(e.target.value) }))} /></div>
            <button className="btn btn-primary" onClick={saveSettings} disabled={saving}>Save Settings</button>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Operator Profile</div></div>
          <div className="form-container">
            <div className="form-group"><label>Name</label><input className="form-control" value={profile.operatorName} onChange={e => setProfile(p => ({ ...p, operatorName: e.target.value }))} /></div>
            <div className="form-group"><label>Role</label><select className="filter-select" value={profile.operatorRole} onChange={e => setProfile(p => ({ ...p, operatorRole: e.target.value }))}><option>SOC Analyst</option><option>SOC Manager</option><option>Security Engineer</option><option>Administrator</option></select></div>
            <div className="form-group"><label>Team</label><input className="form-control" value={profile.operatorTeam} onChange={e => setProfile(p => ({ ...p, operatorTeam: e.target.value }))} /></div>
            <button className="btn btn-primary" onClick={saveProfile} disabled={saving}>Save Profile</button>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header"><div className="card-title">Data Management</div></div>
        <div style={{ display: 'flex', gap: 12 }}>
          <button className="btn btn-primary" onClick={handleSeed} disabled={seeding}>{seeding ? 'Loading...' : 'Load Seed Data'}</button>
          <button className="btn btn-danger" onClick={handleReset} disabled={resetting}>{resetting ? 'Resetting...' : 'Reset All Data'}</button>
        </div>
        <div className="hint" style={{ marginTop: 8, fontSize: 11, color: 'var(--text-secondary)' }}>Seed data loads sample incidents, rules, threats, assets, and traffic. Reset deletes all data permanently.</div>
      </div>
    </>
  );
}
