import { NextResponse, type NextRequest } from "next/server";
import { withCors, handleOptions } from "@/helpers/cors";
import { setCookie } from "@/helpers/cookies";
import { NONCE_TTL_SECONDS } from "@/helpers/env";
import type { NextRequest } from "next/server";

function makeNonce() {
  const arr = new Uint8Array(24);
  crypto.getRandomValues(arr);
  return Buffer.from(arr).toString("base64url");
}

export async function OPTIONS(req: NextRequest) {
  return handleOptions(req);
}

export async function GET(req: NextRequest) {
  const nonce = makeNonce();
  const res = NextResponse.json({ nonce }, { status: 200 });
  setCookie(res, "tc_nonce", nonce, {
    httpOnly: true,
    sameSite: "lax",
    secure: undefined,
    path: "/",
    maxAge: NONCE_TTL_SECONDS
  });
  return withCors(req, res);
}
