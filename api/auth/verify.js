// api/auth/verify.js
// SIWE Verify (mit Link-Unterstützung) – präzise Debug-Stages & robuste Catch-Punkte.

import crypto from "node:crypto";
import { withCors } from "../../helpers/cors.js";

const ALLOWED_DOMAINS = new Set(["tonechain.app", "concave-device-193297.framer.app"]);
const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];
const ALLOWED_CHAINS = new Set([1, 11155111]);
const MAX_AGE_MIN = 10;
const MAX_SKEW_MS = 5 * 60 * 1000;

const COOKIE_NONCE = "tc_nonce";
const COOKIE_SESSION = "tc_session";
const SESSION_TTL_SEC = 60 * 60 * 24;
const SESSION_SECRET = process.env.SESSION_SECRET || null;

const DEBUG_SIWE = process.env.DEBUG_SIWE === "1";

// ---------- small utils ----------
function setHdr(res, k, v) { try { res.setHeader(k, v); } catch {} }
function stage(res, label, extra) {
  setHdr(res, "X-TC-Debug", label);
  if (DEBUG_SIWE && extra !== undefined) {
    console.log("[verify]", label, typeof extra === "object" ? JSON.stringify(extra) : String(extra));
  }
}
function errHdr(res, e) {
  const msg = (e && (e.body || e.message)) ? String(e.body || e.message) : String(e);
  setHdr(res, "X-TC-Error", msg.slice(0, 240));
}
function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "SameSite=None", "Secure", "Partitioned"];
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), parts.join("; ")]);
}
function clearCookie(res, name) {
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure; Partitioned`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), del]);
}
function deny(res, status, body) {
  try { clearCookie(res, COOKIE_SESSION); } catch {}
  return res.status(status).json(body);
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const hit = raw.split(/;\s*/).find(s => s.startsWith(name + "="));
  if (!hit) return null;
  const val = hit.split("=").slice(1).join("=");
  try { return decodeURIComponent(val); } catch { return val; }
}
function withinAge(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  const age = Math.abs(Date.now() - t);
  return age <= (MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS);
}
function addrEq(a, b) {
  return String(a || "").toLowerCase() === String(b || "").toLowerCase();
}
function readBearer(req) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

// toleranter SIWE-Parser (Linebreaks normalisiert)
function parseSiweMessage(input) {
  if (!input || typeof input !== "string") return null;
  let msg = input.replace(/\r\n/g, "\n").replace(/^\uFEFF/, "");
  const firstLine = (msg.split("\n")[0] || "").trim();
  const domain = firstLine.split(/\s+/)[0] || "";

  let address = (msg.split("\n")[1] || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    const mAddr = msg.match(/(?:^|\n)\s*(0x[a-fA-F0-9]{40})\s*(?:$|\n)/m);
    address = mAddr ? mAddr[1] : "";
  }

  const pick = (labelRe) => {
    const re = new RegExp(`(?:^|\\n)${labelRe}\\s*:\\s*([^\\n]+)`, "i");
    const m = msg.match(re);
    return m ? m[1].trim() : null;
  };

  const uri = pick("(?:URI)");
  const version = pick("(?:Version)");
  const chainRaw = pick("(?:Chain\\s*ID|ChainID|Chain-?ID)");
  const nonce = pick("(?:Nonce)");
  const issuedAt = pick("(?:Issued\\s*At|IssuedAt)");

  let chainId = null;
  if (chainRaw != null) {
    const num = chainRaw.match(/(\d+)/);
    if (num) chainId = Number(num[1]);
  }

  if (!domain || !address || !uri || !version || !chainId || !nonce || !issuedAt) return null;
  return { domain, address, uri, version, chainId, nonce, issuedAt };
}

// ---------- handler ----------
async function handler(req, res) {
  res.setHeader("Access-Control-Expose-Headers", "X-TC-Debug, X-TC-Error");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok:false, code:"METHOD_NOT_ALLOWED" });

  try {
    const intent = String(req.headers["x-tc-intent"] || req.headers["X-TC-Intent"] || "");
    const bearer = readBearer(req);
    stage(res, "recv", { intent, hasBearer: !!bearer });

    // Body tolerant parsen + normalisieren
    stage(res, "parse-body:start");
    let body = req.body;
    if (!body || typeof body !== "object") {
      try { body = JSON.parse(req.body || "{}"); } catch { body = {}; }
    }
    let message = body?.message;
    const signature = body?.signature;

    if (typeof message === "string") {
      if (message.indexOf("\r\n") !== -1) message = message.replace(/\r\n/g, "\n");
      if (message.indexOf("\\n") !== -1 && message.indexOf("\n") === -1) message = message.replace(/\\n/g, "\n");
      message = message.replace(/^\uFEFF/, "");
    }
    if (!message || !signature) return deny(res, 400, { ok:false, code:"INVALID_PAYLOAD" });
    stage(res, "parse-body:ok", { msgLen: String(message).length });

    // Nonce prüfen
    stage(res, "nonce:get");
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    if (!cookieNonce) return deny(res, 400, { ok:false, code:"MISSING_SERVER_NONCE" });

    // SIWE parse + Policy
    stage(res, "siwe:parse");
    const siwe = parseSiweMessage(String(message));
    if (!siwe) return deny(res, 400, { ok:false, code:"INVALID_SIWE_FORMAT" });
    if (!ALLOWED_DOMAINS.has(siwe.domain)) return deny(res, 400, { ok:false, code:"DOMAIN_NOT_ALLOWED" });

    stage(res, "siwe:uri");
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p))) return deny(res, 400, { ok:false, code:"URI_NOT_ALLOWED" });
    } catch {
      return deny(res, 400, { ok:false, code:"URI_NOT_ALLOWED" });
    }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return deny(res, 400, { ok:false, code:"CHAIN_NOT_ALLOWED" });
    if (!withinAge(siwe.issuedAt)) return deny(res, 400, { ok:false, code:"MESSAGE_TOO_OLD" });
    if (siwe.nonce !== cookieNonce) return deny(res, 401, { ok:false, code:"NONCE_MISMATCH" });

    // Ethers Verify
    stage(res, "ethers:import");
    const ethersMod = await import("ethers");
    const verify =
      ethersMod.verifyMessage ||
      (ethersMod.default && ethersMod.default.verifyMessage) ||
      (ethersMod.utils && ethersMod.utils.verifyMessage);
    if (typeof verify !== "function") return deny(res, 500, { ok:false, code:"VERIFY_UNAVAILABLE" });

    stage(res, "ethers:verify");
    const recovered = await verify(String(message), String(signature));
    if (!addrEq(recovered, siwe.address)) return deny(res, 401, { ok:false, code:"ADDRESS_MISMATCH" });

    // Supabase init
    stage(res, "db:init");
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    try {
      const u = new URL(SUPABASE_URL);
      setHdr(res, "X-TC-SB-Host", u.host);
      setHdr(res, "X-TC-SB-Path", u.pathname || "/");
    } catch {}
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return deny(res, 500, { ok:false, code:"SERVER_CONFIG_MISSING" });
    // Hinweis, ohne Secrets zu leaken
    if (/\/rest\/v1|\/auth\/v1/i.test(SUPABASE_URL)) {
      errHdr(res, "SUPABASE_URL_SUSPICIOUS: should be https://<ref>.supabase.co");
    }
    const { createClient } = await import("@supabase/supabase-js");
    const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

    // Wallet lesen
    stage(res, "db:check-wallet");
    let walletRow = null;
    try {
      const { data, error } = await sbAdmin
        .from("wallets")
        .select("address,user_id")
        .eq("address", String(siwe.address || "").toLowerCase())
        .maybeSingle();
      if (error) {
        errHdr(res, error);
        return deny(res, 500, { ok:false, code:"DB_SELECT_ERROR" });
      }
      walletRow = data || null;
    } catch (e) {
      errHdr(res, "DB_SELECT_THROWN:" + (e?.message || e));
      return deny(res, 500, { ok:false, code:"DB_SELECT_THROWN" });
    }

    let isRegistered = !!walletRow;
    let walletUserId = walletRow?.user_id ?? null;

    // aktiver E-Mail-Bearer?
    stage(res, "db:get-bearer");
    let emailProfileId = null;
    if (bearer) {
      stage(res, "db:get-bearer:call");
      try {
        const { data: authData, error: authErr } = await sbAdmin.auth.getUser(bearer);
        stage(res, "db:get-bearer:ok", { hasError: !!authErr });
        if (!authErr) {
          const authUserId = authData?.user?.id || null;
          if (authUserId) {
            const { data: prof } = await sbAdmin
              .from("profiles")
              .select("id")
              .eq("user_id", authUserId)
              .maybeSingle();
            emailProfileId = prof?.id ?? null;
          }
        }
      } catch (e) {
        // Falls genau hier „invalid media type“ entsteht, sehen wir es eindeutig
        stage(res, "db:get-bearer:throw");
        errHdr(res, e);
        return deny(res, 500, { ok: false, code: "AUTH_GETUSER_FAILED" });
      }
    }

    // LINK-Modus
    const addressLower = String(siwe.address || "").toLowerCase();
    if (intent === "link") {
      stage(res, "link:begin", { hasBearer: !!bearer, emailProfileId: !!emailProfileId });
      if (!bearer || !emailProfileId) return deny(res, 403, { ok:false, code:"LINK_REQUIRES_VALID_BEARER" });

      if (walletUserId && walletUserId !== emailProfileId) {
        return deny(res, 409, { ok:false, code:"WALLET_ALREADY_LINKED", message:"This wallet is already linked to another profile." });
      }

      if (!isRegistered) {
        try {
          const { error: insErr } = await sbAdmin
            .from("wallets")
            .insert({ address: addressLower, user_id: emailProfileId });
          if (insErr) {
            const { data: again } = await sbAdmin
              .from("wallets")
              .select("address,user_id")
              .eq("address", addressLower)
              .maybeSingle();
            const uid = again?.user_id ?? null;
            if (uid && uid !== emailProfileId) {
              return deny(res, 409, { ok:false, code:"WALLET_ALREADY_LINKED", message:"This wallet is already linked to another profile." });
            }
            if (!uid) return deny(res, 500, { ok:false, code:"DB_UPSERT_ERROR" });
          }
          isRegistered = true; walletUserId = emailProfileId;
        } catch (e) {
          errHdr(res, "DB_INSERT_THROWN:" + (e?.message || e));
          return deny(res, 500, { ok:false, code:"DB_INSERT_THROWN" });
        }
      } else if (!walletUserId) {
        try {
          const { data: upd, error: linkErr } = await sbAdmin
            .from("wallets")
            .update({ user_id: emailProfileId })
            .eq("address", addressLower)
            .is("user_id", null)
            .select("user_id");
          if (linkErr) return deny(res, 500, { ok:false, code:"LINK_ERROR" });
          if (!upd || upd.length === 0) {
            const { data: again } = await sbAdmin
              .from("wallets")
              .select("address,user_id")
              .eq("address", addressLower)
              .maybeSingle();
            const uid = again?.user_id ?? null;
            if (uid && uid !== emailProfileId) {
              return deny(res, 409, { ok:false, code:"WALLET_ALREADY_LINKED", message:"This wallet is already linked to another profile." });
            }
            if (!uid) return deny(res, 500, { ok:false, code:"LINK_ERROR" });
          }
          walletUserId = emailProfileId;
        } catch (e) {
          errHdr(res, "DB_UPDATE_THROWN:" + (e?.message || e));
          return deny(res, 500, { ok:false, code:"DB_UPDATE_THROWN" });
        }
      }
    }

    // NORMAL-Gate
    if (intent !== "link") {
      stage(res, "normal:gate", { isRegistered, walletUserId, emailProfileId: !!emailProfileId });
      if (!isRegistered) return deny(res, 403, { ok:false, code:"WALLET_NOT_REGISTERED", message:"No account found for this wallet. Please sign up or link first." });
      if (!walletUserId) return deny(res, 409, { ok:false, code:"WALLET_UNASSIGNED", message:"This wallet is not linked to any profile yet. Use Link mode." });
      if (emailProfileId && walletUserId !== emailProfileId) {
        return deny(res, 409, { ok:false, code:"OTHER_ACCOUNT_ACTIVE", message:"Another account is active via email. Use Link mode." });
      }
    }

    // userId final
    stage(res, "user:resolve");
    let userId = walletUserId ?? null;
    if (!userId && isRegistered) {
      try {
        const { data: row2 } = await sbAdmin
          .from("wallets")
          .select("user_id")
          .eq("address", addressLower)
          .maybeSingle();
        userId = row2?.user_id ?? null;
      } catch (e) {
        errHdr(res, "DB_RESOLVE_THROWN:" + (e?.message || e));
        return deny(res, 500, { ok:false, code:"DB_RESOLVE_THROWN" });
      }
    }
    if (!userId) return deny(res, 403, { ok:false, code:"NO_USER_FOR_WALLET", message:"Wallet has no associated user. Link required." });

    // Session setzen
    stage(res, "session:set");
    const payload = { v: 1, addr: addressLower, userId, ts: Date.now(), exp: Date.now() + SESSION_TTL_SEC * 1000 };
    const raw = JSON.stringify(payload);
    const sig = sign(raw);
    const sessionValue = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");

    clearCookie(res, COOKIE_NONCE);
    setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });

    stage(res, "ok");
    return res.status(200).json({ ok:true, address: addressLower, userId, linked: intent === "link" });
  } catch (e) {
    console.error("[SIWE verify] unexpected error:", e);
    stage(res, "unexpected");
    errHdr(res, e);
    return deny(res, 500, { ok:false, code:"INTERNAL_ERROR" });
  }
}

export default withCors(handler);
export const config = { runtime: "nodejs" };
