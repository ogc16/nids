import { NextRequest, NextResponse } from "next/server";
import { authenticate } from "@/lib/auth";
import { handleApiError } from "@/lib/errors";
import { auditLog } from "@/lib/db";

export async function POST(request: NextRequest) {
  try {
    const user = await authenticate(request);
    auditLog(user.id, "logout", "User logged out", request.headers.get("x-forwarded-for") || "unknown");

    const response = NextResponse.json({ status: "ok", message: "Logged out" });
    response.cookies.set("nids_token", "", { httpOnly: true, sameSite: "lax", path: "/", maxAge: 0 });
    response.cookies.set("csrf-token", "", { httpOnly: false, sameSite: "lax", path: "/", maxAge: 0 });
    return response;
  } catch (err) {
    return handleApiError(err);
  }
}
