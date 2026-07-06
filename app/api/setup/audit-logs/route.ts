import { NextRequest, NextResponse } from 'next/server';
const db = require('@/lib/db');
const { getUserFromRequest } = require('@/lib/route-adapter');

export async function GET(request: NextRequest) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }

  const { searchParams } = request.nextUrl;
  const logs = db.readTable('audit-logs');
  const page = parseInt(searchParams.get('page') || '1');
  const limit = Math.min(100, parseInt(searchParams.get('limit') || '20'));
  const action = searchParams.get('action') || '';
  const userId = searchParams.get('userId') || '';

  let filtered = logs;
  if (action) filtered = filtered.filter((l: any) => l.action === action);
  if (userId) filtered = filtered.filter((l: any) => String(l.userId) === userId);

  return NextResponse.json({
    items: filtered.slice((page - 1) * limit, (page - 1) * limit + limit),
    total: filtered.length,
    page,
    limit
  });
}
