'use client';

export function Card({ title, children, className = '', style }: { title?: string; children: React.ReactNode; className?: string; style?: React.CSSProperties }) {
  return (
    <div className={`card ${className}`.trim()} style={style}>
      {title && (
        <div className="card-header">
          <div className="card-title">{title}</div>
        </div>
      )}
      {children}
    </div>
  );
}
