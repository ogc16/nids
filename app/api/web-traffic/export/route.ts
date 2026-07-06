import { NextRequest, NextResponse } from 'next/server';
import { getUserFromRequest } from '@/lib/route-adapter';
import db from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const user = getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const data = db.readTable('network-traffic').filter((f: any) => f.httpMethod);
  if (data.length === 0) return NextResponse.json({ error: 'No web traffic data' }, { status: 404 });
  const headers = ['timestamp','srcIp','destIp','srcPort','destPort','protocol','httpMethod','httpUri','httpStatus','httpHost','httpUserAgent','httpContentType','bytes','duration','status'];
  const csv = [headers.join(','), ...data.map((row: any) => headers.map((h: string) => {
    const val = row[h];
    if (val === null || val === undefined) return '';
    let str = String(val);
    if (['=', '+', '-', '@', '\t'].includes(str[0])) str = "'" + str;
    return str.includes(',') || str.includes('"') || str.includes('\n') ? `"${str.replace(/"/g, '""')}"` : str;
  }).join(','))].join('\n');
  return new NextResponse(csv, {
    headers: {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="web-traffic-${new Date().toISOString().split('T')[0]}.csv"`
    }
  });
}
