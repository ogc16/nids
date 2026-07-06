import { NextRequest, NextResponse } from 'next/server';
import { getUserFromRequest } from '@/lib/route-adapter';
import { isWebFlow } from '@/lib/traffic-helpers';
import db from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  getUserFromRequest(req);
  const traffic = db.readTable('network-traffic').filter(isWebFlow);
  const methodDist: Record<string, number> = {};
  const statusGroups: Record<string, number> = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
  const uriCount: Record<string, number> = {};
  const hostCount: Record<string, number> = {};
  traffic.forEach((f: any) => {
    if (f.httpMethod) methodDist[f.httpMethod] = (methodDist[f.httpMethod] || 0) + 1;
    if (f.httpStatus) statusGroups[Math.floor(f.httpStatus / 100) + 'xx'] = (statusGroups[Math.floor(f.httpStatus / 100) + 'xx'] || 0) + 1;
    if (f.httpUri) uriCount[f.httpUri] = (uriCount[f.httpUri] || 0) + 1;
    if (f.httpHost) hostCount[f.httpHost] = (hostCount[f.httpHost] || 0) + 1;
  });
  return NextResponse.json({
    totalRequests: traffic.length,
    methodDistribution: Object.entries(methodDist).map(([method, count]) => ({ method, count })),
    statusCodeGroups: statusGroups,
    topUris: Object.entries(uriCount).sort((a: any, b: any) => b[1] - a[1]).slice(0, 10).map(([uri, count]) => ({ uri, count })),
    topHosts: Object.entries(hostCount).sort((a: any, b: any) => b[1] - a[1]).slice(0, 10).map(([host, count]) => ({ host, count })),
    errorRate: traffic.length > 0 ? parseFloat((((statusGroups['4xx'] || 0) + (statusGroups['5xx'] || 0)) / traffic.length * 100).toFixed(1)) : 0,
    uniqueUris: Object.keys(uriCount).length,
    uniqueHosts: Object.keys(hostCount).length
  });
}
