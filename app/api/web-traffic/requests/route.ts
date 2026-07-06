import { NextRequest, NextResponse } from 'next/server';
import { getUserFromRequest } from '@/lib/route-adapter';
import { evaluateTokens, isWebFlow } from '@/lib/traffic-helpers';
import config from '@/lib/config';
import db from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  getUserFromRequest(req);
  let data = db.readTable('network-traffic').filter(isWebFlow);
  const filter = req.nextUrl.searchParams.get('displayFilter') || '';
  if (filter) {
    try {
      const tokens = filter.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
      data = data.filter((item: any) => {
        try { return evaluateTokens(tokens, item); } catch { return true; }
      });
    } catch {}
  }
  const method = req.nextUrl.searchParams.get('method') || '';
  const status = req.nextUrl.searchParams.get('status') || '';
  const search = req.nextUrl.searchParams.get('search') || '';
  if (method) data = data.filter((f: any) => f.httpMethod === method);
  if (status) data = data.filter((f: any) => String(f.httpStatus).startsWith(status));
  if (search) data = data.filter((f: any) => (f.httpUri || '').toLowerCase().includes(search) || (f.httpHost || '').toLowerCase().includes(search) || String(f.httpStatus).includes(search));
  const page = Math.max(1, parseInt(req.nextUrl.searchParams.get('page') || '1'));
  const limit = Math.min(config.maxPageSize, Math.max(1, parseInt(req.nextUrl.searchParams.get('limit') || String(config.defaultPageSize))));
  const totalFiltered = data.length;
  const items = data.slice((page - 1) * limit, (page - 1) * limit + limit);
  return NextResponse.json({ items, pagination: { page, limit, total: totalFiltered, totalFiltered, totalPages: Math.ceil(totalFiltered / limit) } });
}
