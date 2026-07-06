import { NextRequest, NextResponse } from 'next/server';
const { updateUserRoute, deleteUserRoute } = require('@/lib/auth');
const { createMockReq, createMockRes, getUserFromRequest } = require('@/lib/route-adapter');

export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (user.role !== 'admin') {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  try {
    const { id } = await params;
    const body = await request.json();
    const req = createMockReq(request, { id });
    req.body = body;
    req.user = user;

    const res = createMockRes();
    updateUserRoute(req, res);

    return NextResponse.json(res._getBody(), { status: res._getStatus() });
  } catch (err: any) {
    if (err.isOperational) {
      return NextResponse.json({ error: err.message }, { status: err.statusCode || 400 });
    }
    return NextResponse.json({ error: err.message || 'Failed to update user' }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const user = getUserFromRequest(request);
  if (!user) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (user.role !== 'admin') {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  try {
    const { id } = await params;
    const req = createMockReq(request, { id });
    req.user = user;

    const res = createMockRes();
    deleteUserRoute(req, res);

    return new NextResponse(null, { status: res._getStatus() });
  } catch (err: any) {
    if (err.isOperational) {
      return NextResponse.json({ error: err.message }, { status: err.statusCode || 400 });
    }
    return NextResponse.json({ error: err.message || 'Failed to delete user' }, { status: 500 });
  }
}
