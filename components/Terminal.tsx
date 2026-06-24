'use client';

import { useEffect, useRef, useState } from 'react';

interface AuditEntry {
  timestamp: string;
  event: string;
  user?: { username: string };
  method?: string;
  path?: string;
  table?: string;
  id?: string;
}

export default function Terminal() {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [collapsed, setCollapsed] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (collapsed) return;
    const fetchLogs = () => {
      fetch('/api/audit/log?limit=50')
        .then(r => r.ok ? r.json() : [])
        .then(res => {
          setLogs(Array.isArray(res) ? res : []);
        })
        .catch(() => {});
    };
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [collapsed]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className={`terminal ${collapsed ? 'terminal-collapsed' : ''}`}>
      <div className="terminal-header" onClick={() => setCollapsed(!collapsed)}>
        <span className="terminal-dot" />
        <span className="terminal-title">Console</span>
        <span className="terminal-toggle">{collapsed ? '\u25B2' : '\u25BC'}</span>
      </div>
      {!collapsed && (
        <div className="terminal-body">
          {logs.length === 0 && <div className="terminal-line">Waiting for events...</div>}
          {logs.map((log, i) => (
            <div key={i} className="terminal-line">
              <span className="terminal-time">{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : ''}</span>
              <span className="terminal-arrow">&rarr;</span>
              <span className={`terminal-action terminal-action-${log.event === 'create' ? 'create' : log.event === 'delete' ? 'delete' : 'update'}`}>{log.event}</span>
              {log.table && <span className="terminal-table">[{log.table}]</span>}
              <span className="terminal-msg">{log.path || ''}{log.id ? ` #${log.id}` : ''}</span>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      )}
    </div>
  );
}
