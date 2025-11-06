// api/auth/peek.js
// Liest die SIWE-Session (tc_session) aus, prüft Signatur & Ablauf
// und gibt den aktuellen Auth-Status zurück.

import { withCors } from "../../helpers/cors.js";
import crypto from "node:crypto";

const COOKIE_SESSION = "tc_session";
const SESSION_SECRET = process.env.SESSION_SECRET || null;

function setDebug(res, msg) { try { res.setHeader("X-TC-Debug", msg); } catch {} }

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const hit = raw.split(/;\s*/).find((s) => s.startsWith(name + "="));
  return hit ? decodeURIComponent(hit.split("=").slice(1).join("=")) : null;
}

function clearCookie(res, name) {
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure; Partitioned`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), del]);
}

function hmac(payload) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
}

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

async function handler(req, res) {
  // Preflight wird im withCors erledigt; GET/HEAD erlauben
  if (req.method === "HEAD") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).json({ ok:false, code:"METHOD_NOT_ALLOWED" });

  try {
    const rawCookie = getCookie(req, COOKIE_SESSION);
    if (!rawCookie) {
      setDebug(res, "no-session-cookie");
      return res.status(200).json({ ok:true, authenticated:false });
    }

    // tc_session ist base64(JSON({ raw, sig? }))
    const decoded = Buffer.from(String(rawCookie), "base64").toString("utf8");
    const wrapped = safeJsonParse(decoded);
    if (!wrapped || !wrapped.raw) {
      clearCookie(res, COOKIE_SESSION);
      return res.status(200).json({ ok:true, authenticated:false });
    }

    // Signatur prüfen (wenn SECRET konfiguriert)
    if (SESSION_SECRET) {
      const expected = hmac(wrapped.raw);
      if (!wrapped.sig || wrapped.sig !== expected) {
        setDebug(res, "bad-sig");
        clearCookie(res, COOKIE_SESSION);
        return res.status(200).json({ ok:true, authenticated:false });
      }
    }

    const payload = safeJsonParse(wrapped.raw);
    if (!payload || typeof payload !== "object") {
      clearCookie(res, COOKIE_SESSION);
      return res.status(200).json({ ok:true, authenticated:false });
    }

    // Ablauf prüfen
    if (!payload.exp || Date.now() > Number(payload.exp)) {
      setDebug(res, "expired");
      clearCookie(res, COOKIE_SESSION);
      return res.status(200).json({ ok:true, authenticated:false, expired:true });
    }

    // Minimaldaten für UI
    const result = {
      ok: true,
      authenticated: true,
      address: payload.addr || null,
      userId: payload.userId || null,
      // optional: expiresInMs für UI
      expiresInMs: Number(payload.exp) - Date.now(),
    };

    return res.status(200).json(result);
  } catch (e) {
    console.error("[peek] unexpected error:", e);
    return res.status(500).json({ ok:false, code:"INTERNAL_ERROR" });
  }
}

export default withCors(handler);
export const config = { runtime: "nodejs" };
