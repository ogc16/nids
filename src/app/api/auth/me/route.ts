import { NextRequest, NextResponse } from "next/server";
import { authenticate } from "@/lib/auth";
import { handleApiError } from "@/lib/errors";

export async function GET(request: NextRequest) {
  try {
    const user = await authenticate(request);
    return NextResponse.json({ id: user.id, username: user.username, role: user.role });
  } catch (err) {
    return handleApiError(err);
  }
}
