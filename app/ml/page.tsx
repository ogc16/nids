'use client';

import { useEffect, useState } from 'react';

export default function MlPage() {
  const [models, setModels] = useState<any[]>([]);
  const [thresholdRules, setThresholdRules] = useState<any[]>([]);
  const [dataInput, setDataInput] = useState('');
  const [fieldInput, setFieldInput] = useState('');
  const [anomalyResult, setAnomalyResult] = useState<any>(null);
  const [baselineBuilding, setBaselineBuilding] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [trafficResult, setTrafficResult] = useState<any>(null);
  const [ruleName, setRuleName] = useState('');
  const [ruleField, setRuleField] = useState('');
  const [ruleOp, setRuleOp] = useState('>');
  const [ruleValue, setRuleValue] = useState('');
  const [msg, setMsg] = useState('');

  useEffect(() => {
    fetch('/api/ml/models').then(r => r.json()).then(d => setModels(Array.isArray(d) ? d : d.models || d.items || [])).catch(() => {});
    fetch('/api/ml/threshold-rules').then(r => r.json()).then(d => setThresholdRules(Array.isArray(d) ? d : d.rules || d.items || [])).catch(() => {});
  }, []);

  async function handleDetectAnomalies() {
    if (!dataInput.trim() || !fieldInput.trim()) return;
    setAnomalyResult(null);
    setMsg('');
    try {
      let data;
      try { data = JSON.parse(dataInput); } catch { data = dataInput.split(',').map(Number).filter(n => !isNaN(n)); }
      const res = await fetch('/api/ml/detect-anomalies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data, field: fieldInput, method: 'zscore', threshold: 3 }),
      });
      if (res.ok) setAnomalyResult(await res.json());
      else { const err = await res.json(); setMsg(err.error || 'Detection failed'); }
    } catch { setMsg('Detection failed'); }
  }

  async function handleBuildBaseline() {
    setBaselineBuilding(true);
    setMsg('');
    try {
      const res = await fetch('/api/ml/traffic-baseline', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setMsg(`Baseline built: ${data.recordCount} records`);
      } else {
        const err = await res.json(); setMsg(err.error || 'Failed');
      }
    } catch { setMsg('Failed to build baseline'); }
    finally { setBaselineBuilding(false); }
  }

  async function handleDetectTraffic() {
    setDetecting(true);
    setMsg('');
    try {
      const res = await fetch('/api/ml/detect-traffic-anomalies', { method: 'POST' });
      if (res.ok) setTrafficResult(await res.json());
      else { const err = await res.json(); setMsg(err.error || 'Detection failed'); }
    } catch { setMsg('Detection failed'); }
    finally { setDetecting(false); }
  }

  async function handleCreateRule() {
    if (!ruleName.trim() || !ruleField.trim() || !ruleValue.trim()) return;
    setMsg('');
    try {
      const res = await fetch('/api/ml/threshold-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: ruleName, field: ruleField, operator: ruleOp, value: parseFloat(ruleValue), window: 300, cooldown: 600 }),
      });
      if (res.ok) {
        setMsg('Rule created');
        setRuleName(''); setRuleField(''); setRuleValue('');
        fetch('/api/ml/threshold-rules').then(r => r.json()).then(d => setThresholdRules(Array.isArray(d) ? d : d.rules || d.items || [])).catch(() => {});
      } else {
        const err = await res.json(); setMsg(err.error || 'Failed');
      }
    } catch { setMsg('Failed to create rule'); }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>ML Anomaly Detection</h2>
          <div className="subtitle">Machine learning-based anomaly detection and threshold rules</div>
        </div>
      </div>

      {msg && (
        <div className="toast" style={{ position: 'static', marginBottom: 16 }}>
          {msg}
        </div>
      )}

      <div className="charts-row">
        <div className="card">
          <div className="card-header"><div className="card-title">Detect Anomalies</div></div>
          <div className="form-container">
            <div className="form-group">
              <label>Data (JSON array or comma-separated numbers)</label>
              <textarea className="form-control" rows={3} value={dataInput} onChange={e => setDataInput(e.target.value)} placeholder='[10, 12, 11, 13, 100, 9, 11]' />
            </div>
            <div className="form-group">
              <label>Field name</label>
              <input className="form-control" value={fieldInput} onChange={e => setFieldInput(e.target.value)} placeholder="value" />
            </div>
            <button className="btn btn-primary" onClick={handleDetectAnomalies}>Detect</button>
            {anomalyResult && (
              <pre style={{ marginTop: 12, background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 12, overflow: 'auto' }}>
                {JSON.stringify(anomalyResult, null, 2)}
              </pre>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Traffic Baseline & Detection</div></div>
          <div className="form-container">
            <div className="form-group">
              <button className="btn btn-primary" onClick={handleBuildBaseline} disabled={baselineBuilding} style={{ width: '100%', marginBottom: 8 }}>
                {baselineBuilding ? 'Building...' : 'Build Traffic Baseline'}
              </button>
              <button className="btn btn-info" onClick={handleDetectTraffic} disabled={detecting} style={{ width: '100%' }}>
                {detecting ? 'Detecting...' : 'Detect Traffic Anomalies'}
              </button>
            </div>
            {trafficResult && (
              <pre style={{ marginTop: 8, background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 12, maxHeight: 200, overflow: 'auto' }}>
                {JSON.stringify(trafficResult, null, 2)}
              </pre>
            )}
          </div>
        </div>
      </div>

      <div className="charts-row">
        <div className="card">
          <div className="card-header"><div className="card-title">Create Threshold Rule</div></div>
          <div className="form-container">
            <div className="form-group">
              <label>Name</label>
              <input className="form-control" value={ruleName} onChange={e => setRuleName(e.target.value)} placeholder="High traffic alert" />
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>Field</label>
                <input className="form-control" value={ruleField} onChange={e => setRuleField(e.target.value)} placeholder="bytes" />
              </div>
              <div className="form-group">
                <label>Operator</label>
                <select className="form-control filter-select" value={ruleOp} onChange={e => setRuleOp(e.target.value)}>
                  <option value=">">{'>'}</option>
                  <option value="<">{'<'}</option>
                  <option value=">=">{'>='}</option>
                  <option value="<=">{'<='}</option>
                  <option value="==">{'=='}</option>
                </select>
              </div>
            </div>
            <div className="form-group">
              <label>Value</label>
              <input type="number" className="form-control" value={ruleValue} onChange={e => setRuleValue(e.target.value)} placeholder="10000" />
            </div>
            <button className="btn btn-primary" onClick={handleCreateRule}>Create Rule</button>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Active Threshold Rules ({thresholdRules.length})</div></div>
          {thresholdRules.length > 0 ? (
            <div className="data-table-wrapper">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Field</th>
                    <th>Op</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {thresholdRules.map((r: any, i: number) => (
                    <tr key={i}>
                      <td>{r.name}</td>
                      <td>{r.field}</td>
                      <td>{r.operator}</td>
                      <td>{r.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state" style={{ padding: 20 }}><div>No threshold rules</div></div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header"><div className="card-title">Models ({models.length})</div></div>
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {models.map((m: any, i: number) => (
                <tr key={i}>
                  <td>{m.name}</td>
                  <td>{m.type || m.modelType || '-'}</td>
                  <td>{m.createdAt || m.timestamp ? new Date(m.createdAt || m.timestamp).toLocaleString() : '-'}</td>
                </tr>
              ))}
              {models.length === 0 && (
                <tr><td colSpan={3} style={{ textAlign: 'center', padding: 24, color: 'var(--text-secondary)' }}>No models</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
