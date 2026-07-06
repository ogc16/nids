import { NextRequest, NextResponse } from 'next/server';
import { getUserFromRequest } from '@/lib/route-adapter';
import { evaluateTokens } from '@/lib/traffic-helpers';
import config from '@/lib/config';
import db from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  getUserFromRequest(req);
  let data = db.readTable('network-traffic');
  const filter = req.nextUrl.searchParams.get('displayFilter') || '';
  if (filter) {
    try {
      const tokens = filter.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
      data = data.filter((item: any) => {
        try { return evaluateTokens(tokens, item); } catch { return true; }
      });
    } catch {}
  }
  const page = Math.max(1, parseInt(req.nextUrl.searchParams.get('page') || '1'));
  const limit = Math.min(config.maxPageSize, Math.max(1, parseInt(req.nextUrl.searchParams.get('limit') || String(config.defaultPageSize))));
  const totalFiltered = data.length;
  const offset = (page - 1) * limit;
  const items = data.slice(offset, offset + limit);
  return NextResponse.json({ items, pagination: { page, limit, total: totalFiltered, totalFiltered, totalPages: Math.ceil(totalFiltered / limit) } });
}
