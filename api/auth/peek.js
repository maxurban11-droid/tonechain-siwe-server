// /api/auth/peek.js — robuste SIWE-Session-Inspektion (Node runtime)
import { withCors } from "../../helpers/cors.js";
import crypto from "node:crypto";

/* ==============================
   Konfiguration
============================== */
const COOKIE_SESSION = "tc_session";
// Optional: serverseitige Signaturprüfung
const SESSION_SECRET = process.env.SESSION_SECRET || null;

/* ==============================
   Helpers
============================== */
function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}

function readCookie(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(/;\s*/)) {
    const [k, ...rest] = part.split("=");
    if (k === name) return decodeURIComponent(rest.join("=") || "");
  }
  return null;
}

function pushCookie(res, cookie) {
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", [cookie]);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie]);
  else res.setHeader("Set-Cookie", [String(prev), cookie]);
}

function clearCookie(res, name) {
  // Cross-site kompatibel löschen
  pushCookie(res, `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`);
}

/**
 * tc_session-Format (Base64):
 *   { raw, sig? }  // JSON-stringifiziert, dann Base64
 *   raw = JSON.stringify({ v:1, addr:string, ts:number, exp:number, userId?:string })
 *   sig = HMAC-SHA256(raw, SESSION_SECRET)   // optional
 */
function decodeSessionCookie(sessionCookie) {
  if (!sessionCookie) return null;
  let envelope;
  try {
    const json = Buffer.from(sessionCookie, "base64").toString("utf8");
    envelope = JSON.parse(json);
  } catch {
    return null;
  }
  if (!envelope || typeof envelope !== "object") return null;

  const { raw, sig } = envelope;
  if (typeof raw !== "string") return null;

  if (SESSION_SECRET) {
    const expect = sign(raw);
    if (!sig || sig !== expect) return { invalid: true };
  }

  try {
    const payload = JSON.parse(raw);
    if (
      !payload ||
      typeof payload !== "object" ||
      payload.v !== 1 ||
      !payload.addr ||
      !Number.isFinite(payload.ts) ||
      !Number.isFinite(payload.exp)
    ) {
      return null;
    }
    return { payload };
  } catch {
    return null;
  }
}

/* ==============================
   Core-Handler (CORS via withCors)
============================== */
async function core(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  }

  const sessionCookie = readCookie(req, COOKIE_SESSION);
  if (!sessionCookie) {
    return res.status(200).json({
      ok: true,
      hasSession: false,
      sessionAddress: null,
    });
  }

  const decoded = decodeSessionCookie(sessionCookie);
  if (!decoded || decoded.invalid) {
    clearCookie(res, COOKIE_SESSION);
    return res.status(200).json({
      ok: true,
      hasSession: false,
      sessionAddress: null,
    });
  }

  const { payload } = decoded; // { v, addr, ts, exp, userId? }
  const now = Date.now();
  if (payload.exp <= now) {
    clearCookie(res, COOKIE_SESSION);
    return res.status(200).json({
      ok: true,
      hasSession: false,
      sessionAddress: null,
      expired: true,
    });
  }

  return res.status(200).json({
    ok: true,
    hasSession: true,
    sessionAddress: payload.addr,
    // optional:
    // userId: payload.userId ?? null,
    // issuedAt: payload.ts,
    // expiresAt: payload.exp,
  });
}

export default withCors(core);
// Nicht als Edge laufen lassen
export const config = { runtime: "nodejs" };
