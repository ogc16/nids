import { NextRequest, NextResponse } from 'next/server';
import { getUserFromRequest } from '@/lib/route-adapter';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const user = getUserFromRequest(req);
  if (!user || (user.role !== 'admin' && user.role !== 'analyst')) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }
  const body = await req.json().catch(() => ({}));
  const { interval = 5000 } = body;
  const token = req.cookies.get('token')?.value;
  const timer = setInterval(() => {
    fetch(`http://localhost:${process.env.PORT || 3000}/api/network-traffic/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: `token=${token}` }
    }).catch(() => {});
  }, interval);
  req.signal.addEventListener('abort', () => clearInterval(timer));
  return NextResponse.json({ status: 'simulation_started', interval });
}
