import { NextRequest, NextResponse } from 'next/server';
const { audit } = require('@/lib/audit');
const { getUserFromRequest, createMockReq } = require('@/lib/route-adapter');

export async function POST(request: NextRequest) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (user.role !== 'admin') {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  try {
    require('@/lib/seed')();
    const req = createMockReq(request);
    audit('data_seeded', req);
    return NextResponse.json({ status: 'ok', message: 'Seed data generated' });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
