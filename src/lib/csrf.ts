import { NextRequest, NextResponse } from "next/server";

const CSRF_COOKIE = "csrf-token";

export async function generateCsrfToken(): Promise<string> {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function setCsrfCookie(response: NextResponse, token: string): void {
  response.cookies.set(CSRF_COOKIE, token, {
    httpOnly: false,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });
}

export async function validateCsrf(request: NextRequest): Promise<boolean> {
  if (["GET", "HEAD", "OPTIONS"].includes(request.method)) {
    return true;
  }

  const csrfCookie = request.cookies.get(CSRF_COOKIE)?.value;
  if (!csrfCookie) {
    return true;
  }

  const csrfHeader = request.headers.get("x-csrf-token");
  if (!csrfHeader || csrfHeader !== csrfCookie) {
    return false;
  }

  return true;
}

export async function csrfProtection(request: NextRequest): Promise<NextResponse | null> {
  const isValid = await validateCsrf(request);
  if (!isValid) {
    return NextResponse.json({ error: "Invalid CSRF token" }, { status: 403 });
  }
  return null;
}
