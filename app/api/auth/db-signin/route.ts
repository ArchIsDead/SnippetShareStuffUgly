import { NextRequest, NextResponse } from "next/server";
import { rateLimitCheck, rateLimitResponse, API_LIMITS } from "@/lib/rate-limiter";
import { issueSessionToken, SESSION_COOKIE, SESSION_TTL } from "@/lib/auth";

const GENERIC_ERROR = "Invalid credentials";

function sameOrigin(request: NextRequest) {
  const host = request.headers.get("host") || "";
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");
  if (origin) { try { return new URL(origin).host === host; } catch { return false; } }
  if (referer) { try { return new URL(referer).host === host; } catch { return false; } }
  return true;
}

export async function POST(request: NextRequest) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || request.headers.get("x-real-ip") || "unknown";
  const rl = rateLimitCheck(`auth:${ip}`, API_LIMITS.auth);
  if (!rl.allowed) return rateLimitResponse(rl.resetAt);
  try {
    const body = await request.json().catch(() => null);
    const password = body && typeof body === "object" ? (body as Record<string, unknown>).password : null;
    if (typeof password !== "string" || password.length < 1 || password.length > 4096) return NextResponse.json({ error: GENERIC_ERROR }, { status: 401 });
    const valid = process.env.PW;
    if (!valid) return NextResponse.json({ error: "Server not configured" }, { status: 500 });
    if (password !== valid) return NextResponse.json({ error: GENERIC_ERROR }, { status: 401 });
    const response = NextResponse.json({ ok: true, username: "suic1.de" });
    response.cookies.set(SESSION_COOKIE, issueSessionToken(), { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", maxAge: SESSION_TTL, path: "/" });
    return response;
  } catch { return NextResponse.json({ error: "Internal server error" }, { status: 500 }); }
}
