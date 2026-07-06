import { NextRequest, NextResponse } from 'next/server';
const db = require('@/lib/db');
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
    const tables = ['incidents', 'detection-rules', 'threat-intel', 'network-traffic', 'engineering-tasks', 'network-assets', 'qa-tests', 'playbooks', 'security-policies', 'security-standards', 'automation-logs'];
    tables.forEach((t: string) => db.writeTable(t, []));
    const req = createMockReq(request);
    audit('data_reset', req, { cleared_tables: tables });
    return NextResponse.json({ status: 'ok', message: `Cleared ${tables.length} tables` });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
