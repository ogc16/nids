'use client';

export function StatCard({ label, value, sub, variant, href }: {
  label: string;
  value: React.ReactNode;
  sub?: string;
  variant?: string;
  href?: string;
}) {
  const content = (
    <>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </>
  );
  if (href) {
    return <a href={href} className={`stat-card ${variant || ''}`.trim()} style={{ textDecoration: 'none' }}>{content}</a>;
  }
  return <div className={`stat-card ${variant || ''}`.trim()}>{content}</div>;
}

export function StatCardSmall({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div className="stat-card-small">
      <div className="stat-value" style={color ? { color } : undefined}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
