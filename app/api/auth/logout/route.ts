import { NextRequest, NextResponse } from 'next/server';
const config = require('@/lib/config');
const { createMockReq, createMockRes, getUserFromRequest } = require('@/lib/route-adapter');

export async function POST(request: NextRequest) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }

  const response = NextResponse.json({ status: 'ok', message: 'Logged out' });
  response.cookies.set(config.cookieName, '', { path: '/', maxAge: 0, httpOnly: true, sameSite: 'strict' as const });
  response.cookies.set('csrf-token', '', { path: '/', maxAge: 0, sameSite: 'strict' as const });
  return response;
}
