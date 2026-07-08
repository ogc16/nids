import { NextResponse } from "next/server";

export function handleApiError(err: unknown): NextResponse {
  if (err && typeof err === "object" && "name" in err && (err as { name: string }).name === "AuthError") {
    const authErr = err as unknown as { message: string; statusCode: number };
    return NextResponse.json({ error: authErr.message }, { status: authErr.statusCode });
  }

  if (err && typeof err === "object" && "name" in err && (err as { name: string }).name === "ZodError") {
    return NextResponse.json({ error: "Validation failed" }, { status: 422 });
  }

  console.error("[API Error]", err);
  return NextResponse.json({ error: "Internal server error" }, { status: 500 });
}
