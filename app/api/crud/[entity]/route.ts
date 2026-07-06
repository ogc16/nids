import { NextRequest, NextResponse } from 'next/server';
const db = require('@/lib/db');
const { audit } = require('@/lib/audit');
const { getUserFromRequest, createMockReq } = require('@/lib/route-adapter');

const WRITABLE_TABLES = ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests', 'playbooks', 'security-policies', 'security-standards'];
const READONLY_TABLES = ['network-traffic'];
const ALL_TABLES = [...WRITABLE_TABLES, ...READONLY_TABLES];

function isValidEntity(entity: string): boolean {
  return ALL_TABLES.includes(entity);
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ entity: string }> }) {
  const { entity } = await params;
  if (!isValidEntity(entity)) {
    return NextResponse.json({ error: `Unknown table: ${entity}` }, { status: 404 });
  }

  const user = getUserFromRequest(request);
  const { searchParams } = request.nextUrl;

  if (entity === 'network-traffic') {
    if (!user) return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }

  const result = db.readTablePaginated(entity, Object.fromEntries(searchParams));
  return NextResponse.json(result);
}

export async function POST(request: NextRequest, { params }: { params: Promise<{ entity: string }> }) {
  const { entity } = await params;
  if (!isValidEntity(entity)) {
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
    const nextIdVal = db.nextId(data);
    const item = { id: nextIdVal, ...body };
    data.push(item);
    db.writeTable(entity, data);

    const req = createMockReq(request);
    audit('create', req, { table: entity, id: item.id });

    return NextResponse.json(item, { status: 201 });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Failed to create' }, { status: 500 });
  }
}
