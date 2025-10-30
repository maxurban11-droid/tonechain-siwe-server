import { NextResponse, type NextRequest } from "next/server";
import { withCors, handleOptions } from "@/helpers/cors";

export async function OPTIONS(req: NextRequest) {
  return handleOptions(req);
}

export async function GET(req: NextRequest) {
  const res = NextResponse.json({ ok: true, ts: Date.now() }, { status: 200 });
  return withCors(req, res);
}
