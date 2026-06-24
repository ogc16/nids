'use client';

export function LoadingState({ message = 'Loading...', spinner = false }: { message?: string; spinner?: boolean }) {
  if (spinner) {
    return (
      <div className="loading-overlay">
        <div className="loading-spinner"></div>
        <div className="loading-text">{message}</div>
      </div>
    );
  }
  return (
    <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>
      {message}
    </div>
  );
}
