import { NextResponse, type NextRequest } from "next/server";
import { withCors, handleOptions } from "@/helpers/cors";
import { clearCookie } from "@/helpers/cookies";

export async function OPTIONS(req: NextRequest) {
  return handleOptions(req);
}

export async function POST(req: NextRequest) {
  const res = NextResponse.json({ ok: true }, { status: 200 });
  res.cookies.set("tc_session", "", { httpOnly: true, sameSite:"none", secure:true, path:"/", maxAge:0 });
  res.cookies.set("tc_nonce", "",   { httpOnly: true, sameSite:"none", secure:true, path:"/", maxAge:0 });
  return withCors(req, res);
}
