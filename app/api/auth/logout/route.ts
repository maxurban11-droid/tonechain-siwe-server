import { NextResponse, type NextRequest } from "next/server";
import { withCors, handleOptions } from "@/helpers/cors";
import { clearCookie } from "@/helpers/cookies";

export async function OPTIONS(req: NextRequest) {
  return handleOptions(req);
}

export async function POST(req: NextRequest) {
  const res = NextResponse.json({ ok: true }, { status: 200 });
  clearCookie(res, "tc_session", { httpOnly: true, sameSite: "lax", path: "/" });
  clearCookie(res, "tc_nonce", { httpOnly: true, sameSite: "lax", path: "/" });
  return withCors(req, res);
}
