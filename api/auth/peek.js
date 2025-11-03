// /api/auth/peek.js — robuste SIWE-Session-Inspektion (Node runtime)

import { withCors } from "../../helpers/cors.js";
import crypto from "node:crypto";

/* ==============================
   Konfiguration (konsistent zu verify.js)
============================== */
const COOKIE_SESSION = "tc_session";

// Optional: Wenn gesetzt, werden Sessions serverseitig signiert/geprüft
const SESSION_SECRET = process.env.SESSION_SECRET || null;

// Domains wie in verify.js / nonce.js
const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);

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

function clearCookie(res, name) {
  const prev = /** @type {string[]|undefined} */ (res.getHeader("Set-Cookie"));
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`;
  res.setHeader("Set-Cookie", [...(prev || []), del]);
}

function originAllowed(req) {
  const origin = req.headers.origin || "";
  try {
    if (!origin) return false;
    const u = new URL(origin);
    return ALLOWED_DOMAINS.has(u.hostname);
  } catch {
    return false;
  }
}

/**
 * tc_session-Format (Base64):
 *   { raw, sig? }  // JSON-stringifiziert, dann Base64
 *   raw = JSON.stringify({ v:1, addr:string, ts:number, exp:number })
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

  // Wenn SESSION_SECRET aktiv ist, Sig prüfen
  if (SESSION_SECRET) {
    const expect = sign(raw);
    if (!sig || sig !== expect) return { invalid: true }; // manipuliert
  }

  try {
    const payload = JSON.parse(raw);
    // Minimalvalidierung
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
   Core-Handler
============================== */
async function core(req, res) {
  // CORS identisch zu den anderen Routen halten
  const origin = req.headers.origin || "";
  if (origin && originAllowed(req)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else {
    res.setHeader("Access-Control-Allow-Origin", "null");
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") return res.status(204).end();
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
    // Invalid/manipuliert → Cookie weg
    clearCookie(res, COOKIE_SESSION);
    return res.status(200).json({
      ok: true,
      hasSession: false,
      sessionAddress: null,
    });
  }

  const { payload } = decoded; // { v, addr, ts, exp }
  const now = Date.now();
  if (payload.exp <= now) {
    // Abgelaufen → Cookie löschen
    clearCookie(res, COOKIE_SESSION);
    return res.status(200).json({
      ok: true,
      hasSession: false,
      sessionAddress: null,
      expired: true,
    });
  }

  // Aktiv
  return res.status(200).json({
    ok: true,
    hasSession: true,
    sessionAddress: payload.addr,
    // optional nützlich für Debug/Telemetrie:
    // issuedAt: payload.ts,
    // expiresAt: payload.exp,
    // serverNow: now,
  });
}

export default withCors(core);
