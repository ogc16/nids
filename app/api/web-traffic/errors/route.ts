import { NextRequest, NextResponse } from 'next/server';
import { getUserFromRequest } from '@/lib/route-adapter';
import { isWebFlow } from '@/lib/traffic-helpers';
import db from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  getUserFromRequest(req);
  const traffic = db.readTable('network-traffic').filter(isWebFlow);
  const errors = traffic.filter((f: any) => f.httpStatus && f.httpStatus >= 400);
  const byUri: Record<string, any> = {};
  const byCode: Record<string, number> = {};
  errors.forEach((f: any) => {
    const uri = f.httpUri || '/unknown';
    if (!byUri[uri]) byUri[uri] = { uri, total: 0, '4xx': 0, '5xx': 0 };
    byUri[uri].total++;
    if (f.httpStatus >= 500) byUri[uri]['5xx']++; else byUri[uri]['4xx']++;
    byCode[String(f.httpStatus)] = (byCode[String(f.httpStatus)] || 0) + 1;
  });
  return NextResponse.json({
    totalErrors: errors.length,
    errorRate: traffic.length > 0 ? parseFloat((errors.length / traffic.length * 100).toFixed(1)) : 0,
    byUri: Object.values(byUri).sort((a: any, b: any) => b.total - a.total).slice(0, 20),
    byCode: Object.entries(byCode).sort((a: any, b: any) => b[1] - a[1]).map(([code, count]) => ({ code: parseInt(code), count }))
  });
}
