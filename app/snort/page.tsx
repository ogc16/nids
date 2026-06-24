'use client';

import { useEffect, useState } from 'react';

export default function SnortPage() {
  const [sampleRules, setSampleRules] = useState<any[]>([]);
  const [parseInput, setParseInput] = useState('');
  const [parseResult, setParseResult] = useState<any>(null);
  const [validateInput, setValidateInput] = useState('');
  const [validateResult, setValidateResult] = useState<any>(null);
  const [convertInput, setConvertInput] = useState('');
  const [convertResult, setConvertResult] = useState<any>(null);
  const [flowId, setFlowId] = useState('');
  const [correlateResult, setCorrelateResult] = useState<any>(null);
  const [loading, setLoading] = useState('');

  useEffect(() => {
    fetch('/api/snort/sample-rules').then(r => r.json()).then(setSampleRules).catch(() => {});
  }, []);

  async function apiPost(path: string, body: any) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Request failed' }));
      return { error: err.error };
    }
    return res.json();
  }

  async function handleParse() {
    if (!parseInput.trim()) return;
    setLoading('parse');
    const result = await apiPost('/api/snort/parse', { rule: parseInput });
    setParseResult(result);
    setLoading('');
  }

  async function handleValidate() {
    if (!validateInput.trim()) return;
    setLoading('validate');
    const result = await apiPost('/api/snort/validate', { rule: validateInput });
    setValidateResult(result);
    setLoading('');
  }

  async function handleConvert() {
    if (!convertInput.trim()) return;
    setLoading('convert');
    const result = await apiPost('/api/snort/convert', { rule: convertInput });
    setConvertResult(result);
    setLoading('');
  }

  async function handleCorrelate() {
    if (!flowId.trim()) return;
    setLoading('correlate');
    const result = await apiPost('/api/snort/correlate', { flowId });
    setCorrelateResult(result);
    setLoading('');
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>Snort / Suricata</h2>
          <div className="subtitle">Parse, validate, convert, and correlate Snort/Suricata rules</div>
        </div>
      </div>

      <div className="charts-row">
        <div className="card">
          <div className="card-header"><div className="card-title">Parse Rule</div></div>
          <div className="form-container">
            <div className="form-group">
              <textarea className="form-control" rows={4} value={parseInput} onChange={e => setParseInput(e.target.value)} placeholder='alert tcp any any -> any any (msg:"Test"; sid:1;)' />
            </div>
            <button className="btn btn-primary" onClick={handleParse} disabled={loading === 'parse'}>Parse</button>
            {parseResult && (
              <pre style={{ marginTop: 12, background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 12, overflow: 'auto' }}>
                {JSON.stringify(parseResult, null, 2)}
              </pre>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Validate Rule</div></div>
          <div className="form-container">
            <div className="form-group">
              <textarea className="form-control" rows={4} value={validateInput} onChange={e => setValidateInput(e.target.value)} placeholder='alert tcp any any -> any any (msg:"Test"; sid:1;)' />
            </div>
            <button className="btn btn-primary" onClick={handleValidate} disabled={loading === 'validate'}>Validate</button>
            {validateResult && (
              <div style={{ marginTop: 12 }}>
                <span className={`tag ${validateResult.valid ? 'tag-active' : 'tag-critical'}`}>
                  {validateResult.valid ? 'Valid' : 'Invalid'}
                </span>
                {validateResult.errors?.map((e: string, i: number) => (
                  <div key={i} style={{ color: 'var(--accent-red)', fontSize: 12, marginTop: 4 }}>{e}</div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="charts-row">
        <div className="card">
          <div className="card-header"><div className="card-title">Convert to NIDS Rule</div></div>
          <div className="form-container">
            <div className="form-group">
              <textarea className="form-control" rows={4} value={convertInput} onChange={e => setConvertInput(e.target.value)} placeholder='alert tcp any any -> any any (msg:"Test"; sid:1;)' />
            </div>
            <button className="btn btn-primary" onClick={handleConvert} disabled={loading === 'convert'}>Convert to NIDS</button>
            {convertResult && (
              <pre style={{ marginTop: 12, background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 12, overflow: 'auto' }}>
                {JSON.stringify(convertResult, null, 2)}
              </pre>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Flow Correlator</div></div>
          <div className="form-container">
            <div className="form-group">
              <label>Flow ID</label>
              <input className="form-control" value={flowId} onChange={e => setFlowId(e.target.value)} placeholder="Enter flow ID" />
            </div>
            <button className="btn btn-primary" onClick={handleCorrelate} disabled={loading === 'correlate'}>Correlate</button>
            {correlateResult && (
              <pre style={{ marginTop: 12, background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 12, overflow: 'auto' }}>
                {JSON.stringify(correlateResult, null, 2)}
              </pre>
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header"><div className="card-title">Sample Rules ({sampleRules.length})</div></div>
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Rule</th>
              </tr>
            </thead>
            <tbody>
              {sampleRules.map((r: any, i: number) => (
                <tr key={i}>
                  <td>{i + 1}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{typeof r === 'string' ? r : r.rule || r.content || JSON.stringify(r)}</td>
                </tr>
              ))}
              {sampleRules.length === 0 && (
                <tr><td colSpan={2} style={{ textAlign: 'center', padding: 24, color: 'var(--text-secondary)' }}>No sample rules available</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
