import { NextRequest, NextResponse } from 'next/server';
const db = require('@/lib/db');
const { getUserFromRequest } = require('@/lib/route-adapter');

const ALL_TABLES = ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests', 'playbooks', 'security-policies', 'security-standards', 'network-traffic'];

export async function GET(request: NextRequest, { params }: { params: Promise<{ entity: string }> }) {
  const { entity } = await params;
  if (!ALL_TABLES.includes(entity)) {
    return NextResponse.json({ error: `Unknown table: ${entity}` }, { status: 404 });
  }

  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }

  const data = db.readTable(entity);
  if (data.length === 0) {
    return NextResponse.json({ error: 'No data to export' }, { status: 404 });
  }

  const headers = Object.keys(data[0]);
  const csv = [
    headers.join(','),
    ...data.map((row: any) =>
      headers.map((h: string) => {
        const val = row[h];
        if (val === null || val === undefined) return '';
        let str = String(val);
        if (['=', '+', '-', '@', '\t'].includes(str[0])) str = "'" + str;
        return str.includes(',') || str.includes('"') || str.includes('\n')
          ? `"${str.replace(/"/g, '""')}"`
          : str;
      }).join(',')
    )
  ].join('\n');

  return new NextResponse(csv, {
    headers: {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="${entity}-${new Date().toISOString().split('T')[0]}.csv"`
    }
  });
}
