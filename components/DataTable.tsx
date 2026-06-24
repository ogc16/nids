'use client';

export function DataTable({ columns, data, emptyMessage = 'No data found', rowClass, onRowClick }: {
  columns: { key: string; label: string; render?: (item: any) => React.ReactNode }[];
  data: any[];
  emptyMessage?: string;
  rowClass?: (item: any) => string;
  onRowClick?: (item: any) => void;
}) {
  return (
    <div className="data-table-wrapper">
      <table className="data-table">
        <thead>
          <tr>
            {columns.map(col => <th key={col.key}>{col.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {data.map((item, i) => (
            <tr key={item.id ?? i} className={rowClass ? rowClass(item) : ''} onClick={onRowClick ? () => onRowClick(item) : undefined} style={onRowClick ? { cursor: 'pointer' } : undefined}>
              {columns.map(col => (
                <td key={col.key}>{col.render ? col.render(item) : item[col.key]}</td>
              ))}
            </tr>
          ))}
          {data.length === 0 && (
            <tr>
              <td colSpan={columns.length} style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>
                {emptyMessage}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
