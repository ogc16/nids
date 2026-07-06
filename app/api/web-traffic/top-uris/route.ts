import { NextRequest, NextResponse } from 'next/server';
import { getUserFromRequest } from '@/lib/route-adapter';
import { isWebFlow } from '@/lib/traffic-helpers';
import db from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  getUserFromRequest(req);
  const traffic = db.readTable('network-traffic').filter(isWebFlow);
  const uriCount: Record<string, number> = {};
  traffic.forEach((f: any) => { if (f.httpUri) uriCount[f.httpUri] = (uriCount[f.httpUri] || 0) + 1; });
  const top = Object.entries(uriCount).sort((a: any, b: any) => b[1] - a[1]).slice(0, 20).map(([uri, count]) => ({ uri, count }));
  return NextResponse.json(top);
}
