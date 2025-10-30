import { NextResponse, type NextRequest } from "next/server";
import { withCors, handleOptions } from "@/helpers/cors";
import { clearCookie, setCookie } from "@/helpers/cookies";
import { SESSION_TTL_SECONDS } from "@/helpers/env";
import { SiweMessage } from "siwe";
import { createSessionToken } from "@/helpers/crypto";

export async function OPTIONS(req: NextRequest) {
  return handleOptions(req);
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const { message, signature } = body || {};
    if (!message || !signature) {
      const r = NextResponse.json({ ok: false, error: "Missing message or signature" }, { status: 400 });
      return withCors(req, r);
    }

    const cookieNonce = req.cookies.get("tc_nonce")?.value || null;
    if (!cookieNonce) {
      const r = NextResponse.json({ ok: false, error: "Nonce cookie missing or expired" }, { status: 400 });
      return withCors(req, r);
    }

    const siwe = new SiweMessage(message);
    const fields = await siwe.verify({ signature, nonce: cookieNonce });
    if (!fields.success) {
      const r = NextResponse.json({ ok: false, error: "Invalid SIWE" }, { status: 401 });
      return withCors(req, r);
    }

    const address = siwe.address;
    const token = createSessionToken(address);
    const res = NextResponse.json({ ok: true, address }, { status: 200 });

    setCookie(res, "tc_session", token, {
      httpOnly: true,
      sameSite: "none",
      secure: true,
      path: "/",
      maxAge: SESSION_TTL_SECONDS
    });
    clearCookie(res, "tc_nonce", { httpOnly: true, sameSite: "lax", path: "/" });

    return withCors(req, res);
  } catch (e: any) {
    const r = NextResponse.json({ ok: false, error: e?.message || "Verify failed" }, { status: 500 });
    return withCors(req, r);
  }
}
