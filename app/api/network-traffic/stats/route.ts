import { NextRequest, NextResponse } from 'next/server';
import { getUserFromRequest } from '@/lib/route-adapter';
import db from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  getUserFromRequest(req);
  const traffic = db.readTable('network-traffic');
  const totalBytes = traffic.reduce((sum: number, t: any) => sum + (t.bytes || 0), 0);
  return NextResponse.json({
    totalFlows: traffic.length,
    suspiciousCount: traffic.filter((t: any) => t.status === 'suspicious').length,
    blockedCount: traffic.filter((t: any) => t.status === 'blocked').length,
    allowedCount: traffic.filter((t: any) => t.status === 'allowed').length,
    totalBytes,
    uniqueProtocols: [...new Set(traffic.map((t: any) => t.protocol))].length
  });
}
