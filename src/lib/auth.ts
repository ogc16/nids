import { SignJWT, jwtVerify } from "jose";
import bcrypt from "bcryptjs";
import { NextRequest } from "next/server";

export interface AuthUser {
  id: string;
  username: string;
  role: "admin" | "analyst";
}

const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || "insecure-dev-secret-change-in-production"
);
const COOKIE_NAME = "nids_token";
const SESSION_DURATION = "8h";

export function getJwtSecret(): Uint8Array {
  return JWT_SECRET;
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export async function createToken(user: AuthUser): Promise<string> {
  return new SignJWT({ sub: user.id, username: user.username, role: user.role })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(SESSION_DURATION)
    .sign(JWT_SECRET);
}

export async function verifyToken(token: string): Promise<AuthUser | null> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return {
      id: payload.sub as string,
      username: payload.username as string,
      role: payload.role as "admin" | "analyst",
    };
  } catch {
    return null;
  }
}

export async function authenticate(request: NextRequest): Promise<AuthUser> {
  const token = request.cookies.get(COOKIE_NAME)?.value
    || request.headers.get("Authorization")?.replace("Bearer ", "");

  if (!token) {
    throw new AuthError("Authentication required", 401);
  }

  const user = await verifyToken(token);
  if (!user) {
    throw new AuthError("Invalid or expired token", 401);
  }

  return user;
}

export function authorize(user: AuthUser, ...roles: string[]): void {
  if (roles.length > 0 && !roles.includes(user.role)) {
    throw new AuthError("Insufficient permissions", 403);
  }
}

export class AuthError extends Error {
  constructor(
    message: string,
    public statusCode: number
  ) {
    super(message);
    this.name = "AuthError";
  }
}

export { COOKIE_NAME };
