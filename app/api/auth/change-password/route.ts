import { NextRequest, NextResponse } from 'next/server';
const { changePasswordRoute } = require('@/lib/auth');
const { createMockReq, createMockRes, getUserFromRequest } = require('@/lib/route-adapter');

export async function POST(request: NextRequest) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }

  try {
    const body = await request.json();
    const req = createMockReq(request);
    req.body = body;
    req.user = user;

    const res = createMockRes();
    changePasswordRoute(req, res);

    return NextResponse.json(res._getBody(), { status: res._getStatus() });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Failed to change password' }, { status: 500 });
  }
}
