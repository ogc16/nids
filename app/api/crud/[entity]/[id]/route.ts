import { NextRequest, NextResponse } from 'next/server';
const db = require('@/lib/db');
const { audit } = require('@/lib/audit');
const { getUserFromRequest, createMockReq } = require('@/lib/route-adapter');

const ALL_TABLES = ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests', 'playbooks', 'security-policies', 'security-standards', 'network-traffic'];

export async function GET(request: NextRequest, { params }: { params: Promise<{ entity: string; id: string }> }) {
  const { entity, id: idStr } = await params;
  if (!ALL_TABLES.includes(entity)) {
    return NextResponse.json({ error: `Unknown table: ${entity}` }, { status: 404 });
  }

  const user = getUserFromRequest(request);
  const data = db.readTable(entity);
  const item = data.find((d: any) => d.id === parseInt(idStr));
  if (!item) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  return NextResponse.json(item);
}

export async function PUT(request: NextRequest, { params }: { params: Promise<{ entity: string; id: string }> }) {
  const { entity, id: idStr } = await params;
  if (!ALL_TABLES.includes(entity)) {
    return NextResponse.json({ error: `Unknown table: ${entity}` }, { status: 404 });
  }
  if (entity === 'network-traffic') {
    return NextResponse.json({ error: 'Table is read-only' }, { status: 403 });
  }

  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (user.role !== 'admin' && user.role !== 'analyst') {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  try {
    const body = await request.json();
    const data = db.readTable(entity);
    const idx = data.findIndex((d: any) => d.id === parseInt(idStr));
    if (idx === -1) return NextResponse.json({ error: 'Not found' }, { status: 404 });

    data[idx] = { ...data[idx], ...body, id: data[idx].id };
    db.writeTable(entity, data);

    const req = createMockReq(request);
    audit('update', req, { table: entity, id: data[idx].id, changes: Object.keys(body) });

    return NextResponse.json(data[idx]);
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Failed to update' }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ entity: string; id: string }> }) {
  const { entity, id: idStr } = await params;
  if (!ALL_TABLES.includes(entity)) {
    return NextResponse.json({ error: `Unknown table: ${entity}` }, { status: 404 });
  }
  if (entity === 'network-traffic') {
    return NextResponse.json({ error: 'Table is read-only' }, { status: 403 });
  }

  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (user.role !== 'admin') {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  try {
    const data = db.readTable(entity);
    const idx = data.findIndex((d: any) => d.id === parseInt(idStr));
    if (idx === -1) return NextResponse.json({ error: 'Not found' }, { status: 404 });

    data.splice(idx, 1);
    db.writeTable(entity, data);

    const req = createMockReq(request);
    audit('delete', req, { table: entity, id: parseInt(idStr) });

    return new NextResponse(null, { status: 204 });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Failed to delete' }, { status: 500 });
  }
}
