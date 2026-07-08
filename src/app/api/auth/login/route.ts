import { NextRequest, NextResponse } from "next/server";
import { createToken, verifyPassword } from "@/lib/auth";
import { schemas } from "@/lib/validate";
import { authLimit } from "@/lib/rate-limit";
import { generateCsrfToken, setCsrfCookie } from "@/lib/csrf";
import { getUserByUsername, auditLog } from "@/lib/db";
import { handleApiError } from "@/lib/errors";

export async function POST(request: NextRequest) {
  const rateCheck = authLimit(request);
  if (rateCheck) return rateCheck;

  try {
    const body = await request.json().catch(() => ({}));
    const parsed = schemas.login.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Validation failed", details: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) },
        { status: 422 }
      );
    }

    const { username, password } = parsed.data;

    const user = getUserByUsername(username);
    if (!user) {
      auditLog("unknown", "login_failed", `Failed login for user: ${username}`, request.headers.get("x-forwarded-for") || "unknown");
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      auditLog(user.id, "login_failed", "Invalid password", request.headers.get("x-forwarded-for") || "unknown");
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    auditLog(user.id, "login_success", "Successful login", request.headers.get("x-forwarded-for") || "unknown");

    const token = await createToken({ id: user.id, username: user.username, role: user.role });
    const csrfToken = await generateCsrfToken();
    const response = NextResponse.json({
      token,
      user: { id: user.id, username: user.username, role: user.role },
      mustChangePwd: user.mustChangePwd,
    });

    response.cookies.set("nids_token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 8 * 60 * 60,
    });

    setCsrfCookie(response, csrfToken);

    return response;
  } catch (err) {
    return handleApiError(err);
  }
}
