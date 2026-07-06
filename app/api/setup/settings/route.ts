import { NextRequest, NextResponse } from 'next/server';
const db = require('@/lib/db');
const config = require('@/lib/config');
const { audit } = require('@/lib/audit');
const { getUserFromRequest, createMockReq } = require('@/lib/route-adapter');

export async function GET(request: NextRequest) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }
  const settings = db.readTable('settings');
  return NextResponse.json(settings.length > 0 ? settings[0] : config.defaults || {});
}

export async function PUT(request: NextRequest) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (user.role !== 'admin') {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  try {
    const body = await request.json();
    const data = db.readTable('settings');
    const current = data.length > 0 ? data[0] : {};
    const updated = { ...current, ...body, updatedAt: new Date().toISOString() };
    if (data.length > 0) data[0] = updated; else data.push(updated);
    db.writeTable('settings', data);

    const req = createMockReq(request);
    audit('settings_updated', req, { changes: Object.keys(body) });

    if (body.theme) { try { config.set('theme', body.theme); } catch {} }
    return NextResponse.json(updated);
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Failed to update settings' }, { status: 500 });
  }
}
