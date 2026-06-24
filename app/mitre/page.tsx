'use client';

import { useEffect, useState } from 'react';

export default function MitrePage() {
  const [tactics, setTactics] = useState<any[]>([]);
  const [search, setSearch] = useState('');
  const [techniques, setTechniques] = useState<any[]>([]);
  const [attackType, setAttackType] = useState('');
  const [mappingResult, setMappingResult] = useState<any>(null);

  useEffect(() => { fetch('/api/mitre/tactics').then(r => r.json()).then(setTactics).catch(() => {}); }, []);

  useEffect(() => {
    if (!search.trim()) { setTechniques([]); return; }
    const timer = setTimeout(() => {
      fetch(`/api/mitre/techniques?search=${encodeURIComponent(search)}`).then(r => r.json()).then(setTechniques).catch(() => {});
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  async function handleMap() {
    if (!attackType.trim()) return;
    const res = await fetch('/api/mitre/map-attack-type', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attackType }),
    });
    if (res.ok) setMappingResult(await res.json());
  }

  async function loadTechniques(tacticId: string) {
    const res = await fetch(`/api/mitre/techniques?tactic=${tacticId}`);
    if (res.ok) {
      const data = await res.json();
      setTactics(prev => prev.map(t => t.id === tacticId ? { ...t, techniques: data, expanded: !t.expanded } : { ...t, expanded: t.id === tacticId ? !t.expanded : false }));
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2>MITRE ATT&CK Framework</h2>
          <div className="subtitle">Adversarial tactics, techniques, and common knowledge</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header"><div className="card-title">Search Techniques</div></div>
        <input className="form-control" placeholder="Search techniques..." value={search} onChange={e => setSearch(e.target.value)} style={{ maxWidth: 400 }} />
        {techniques.length > 0 && (
          <div style={{ marginTop: 12 }}>
            {techniques.slice(0, 20).map((t: any, i: number) => (
              <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid rgba(48,54,61,0.3)', fontSize: 13 }}>
                <strong style={{ color: 'var(--accent-blue)' }}>{t.id}</strong>: {t.name}
                <span style={{ color: 'var(--text-secondary)', marginLeft: 8 }}>{t.tactic}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header"><div className="card-title">Attack Type Mapper</div></div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input className="form-control" placeholder="Enter attack type (e.g. C2 Communication)" value={attackType} onChange={e => setAttackType(e.target.value)} style={{ maxWidth: 300 }} />
          <button className="btn btn-primary" onClick={handleMap}>Map to MITRE</button>
        </div>
        {mappingResult && (
          <div style={{ marginTop: 12 }}>
            <div style={{ fontWeight: 600, marginBottom: 8 }}>Mapped Techniques:</div>
            {mappingResult.mappedTechniques?.map((t: any, i: number) => (
              <div key={i} style={{ padding: '4px 0', fontSize: 13 }}><span style={{ color: 'var(--accent-blue)' }}>{t.id}</span>: {t.name}</div>
            ))}
            {mappingResult.recommendedDetections?.length > 0 && (
              <>
                <div style={{ fontWeight: 600, marginTop: 12, marginBottom: 8 }}>Recommended Detections:</div>
                {mappingResult.recommendedDetections.map((d: any, i: number) => (
                  <div key={i} style={{ padding: '4px 0', fontSize: 13, color: 'var(--accent-green)' }}>{d.name || d}</div>
                ))}
              </>
            )}
          </div>
        )}
      </div>

      <div className="groups-container">
        {tactics.map((tactic: any) => (
          <div key={tactic.id} className="group-section">
            <div className="group-header" onClick={() => loadTechniques(tactic.id)} style={{ cursor: 'pointer' }}>
              <span className={`tag tag-csf-${tactic.id.toLowerCase()}`}>{tactic.id}</span>
              {tactic.name}
              <span className="group-count">{tactic.techniqueCount || 0} techniques</span>
            </div>
            {tactic.expanded && tactic.techniques && (
              <div className="group-items">
                {tactic.techniques.map((tech: any, i: number) => (
                  <div key={i} className="group-item">
                    <div className="item-main">
                      <div className="item-title"><span style={{ color: 'var(--accent-blue)' }}>{tech.id}</span> — {tech.name}</div>
                      <div className="item-meta">{tech.description?.slice(0, 120)}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </>
  );
}
