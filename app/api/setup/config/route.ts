import { NextRequest, NextResponse } from 'next/server';
const config = require('@/lib/config');
const { getUserFromRequest } = require('@/lib/route-adapter');

export async function GET(request: NextRequest) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (user.role !== 'admin') {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }
  return NextResponse.json(config.getAll());
}
