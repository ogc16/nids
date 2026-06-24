'use client';

export function Pagination({ page, totalPages, total, onPageChange }: {
  page: number;
  totalPages: number;
  total?: number;
  onPageChange: (page: number) => void;
}) {
  if (totalPages <= 1) return null;
  return (
    <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
      <button className="btn btn-sm" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>Previous</button>
      <span style={{ padding: '4px 12px', color: 'var(--text-secondary)' }}>
        Page {page} of {totalPages}{total !== undefined ? ` (${total} total)` : ''}
      </span>
      <button className="btn btn-sm" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>Next</button>
    </div>
  );
}
