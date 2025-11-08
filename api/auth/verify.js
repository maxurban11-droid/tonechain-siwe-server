// api/auth/verify.js
// SIWE Verify (mit Link-Unterstützung), robuste Debug-Stages, Node runtime.

import crypto from "node:crypto";
import { withCors } from "../../helpers/cors.js";

const ALLOWED_DOMAINS = new Set(["tonechain.app", "concave-device-193297.framer.app"]);
const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];
const ALLOWED_CHAINS = new Set([1, 11155111]); // mainnet + sepolia
const MAX_AGE_MIN = 10;
const MAX_SKEW_MS = 5 * 60 * 1000;

const COOKIE_NONCE = "tc_nonce";
const COOKIE_SESSION = "tc_session";
const SESSION_TTL_SEC = 60 * 60 * 24;
const SESSION_SECRET = process.env.SESSION_SECRET || null;

// ---- Debug helpers ----------------------------------------------------------
const DEBUG_SIWE = process.env.DEBUG_SIWE === "1";
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

// ---- helpers ----------------------------------------------------------------
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

// --------- toleranter SIWE-Parser --------------------------------------------
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

// --------- RAW-Body reader (kritisch: NICHT req.body verwenden) --------------
async function readJsonBody(req) {
  try {
    let raw = "";
    for await (const chunk of req) {
      raw += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    }
    if (!raw) return {};
    try { return JSON.parse(raw); } catch { return {}; }
  } catch {
    return {};
  }
}

// ---- handler ----------------------------------------------------------------
async function handler(req, res) {
  // ⚠️ Nichts Teures vor dem OPTIONS-Return!
  res.setHeader("Access-Control-Expose-Headers", "X-TC-Debug, X-TC-Error, X-TC-CT, X-TC-Nonce-Source");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok:false, code:"METHOD_NOT_ALLOWED" });

  try {
    const intent = String(req.headers["x-tc-intent"] || req.headers["X-TC-Intent"] || "");
    const bearer = readBearer(req);
    stage(res, "recv", { intent, hasBearer: !!bearer });
    setHdr(res, "X-TC-CT", String(req.headers["content-type"] || "")); // debug

    // Body robust einlesen
    stage(res, "parse-body:raw");
    const body = await readJsonBody(req);
    let message = body?.message;
    const signature = body?.signature;

    if (typeof message === "string") {
      if (message.indexOf("\r\n") !== -1) message = message.replace(/\r\n/g, "\n");
      if (message.indexOf("\\n") !== -1 && message.indexOf("\n") === -1) message = message.replace(/\\n/g, "\n");
      message = message.replace(/^\uFEFF/, "");
    }
    if (!message || !signature) return deny(res, 400, { ok:false, code:"INVALID_PAYLOAD" });
    stage(res, "parse-body:ok", { msgLen: String(message).length });

    // Nonce
    stage(res, "nonce:get");
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    const headerNonce = (req.headers["x-tc-nonce"] ? String(req.headers["x-tc-nonce"]) : "").trim() || null;
    const serverNonce = cookieNonce || headerNonce;
    setHdr(res, "X-TC-Nonce-Source", cookieNonce ? "cookie" : (headerNonce ? "header" : "none"));
    if (!serverNonce) return deny(res, 400, { ok:false, code:"MISSING_SERVER_NONCE" });

    // SIWE-Grundvalidierung
    stage(res, "siwe:parse");
    const siwe = parseSiweMessage(String(message));
    if (!siwe) return deny(res, 400, { ok:false, code:"INVALID_SIWE_FORMAT" });
    if (!ALLOWED_DOMAINS.has(siwe.domain)) return deny(res, 400, { ok:false, code:"DOMAIN_NOT_ALLOWED" });

    stage(res, "siwe:uri");
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p))) return deny(res, 400, { ok:false, code:"URI_NOT_ALLOWED" });
    } catch { return deny(res, 400, { ok:false, code:"URI_NOT_ALLOWED" }); }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return deny(res, 400, { ok:false, code:"CHAIN_NOT_ALLOWED" });
    if (!withinAge(siwe.issuedAt)) return deny(res, 400, { ok:false, code:"MESSAGE_TOO_OLD" });
    if (siwe.nonce !== serverNonce) return deny(res, 401, { ok:false, code:"NONCE_MISMATCH" });

    // Signatur prüfen
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

    // Supabase Admin
    stage(res, "db:init");
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return deny(res, 500, { ok:false, code:"SERVER_CONFIG_MISSING" });
    const { createClient } = await import("@supabase/supabase-js");
    const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

    // Wallet-Status
    stage(res, "db:check-wallet");
    const addressLower = String(siwe.address || "").toLowerCase();
    const { data: walletRow, error: wErr } = await sbAdmin
      .from("wallets")
      .select("address,user_id")
      .eq("address", addressLower)
      .maybeSingle();
    if (wErr) return deny(res, 500, { ok:false, code:"DB_SELECT_ERROR" });

    let isRegistered = !!walletRow;
    let walletUserId = walletRow?.user_id ?? null;

    // aktive E-Mail Session?
    stage(res, "db:get-bearer");
    let emailProfileId = null;
    if (bearer) {
      const { data: authData, error: authErr } = await sbAdmin.auth.getUser(bearer);
      if (!authErr) {
        const authUserId = authData?.user?.id || null;
        if (authUserId) {
          const { data: prof } = await sbAdmin.from("profiles").select("id").eq("user_id", authUserId).maybeSingle();
          emailProfileId = prof?.id ?? null;
        }
      }
    }

    // LINK
if (intent === "link") {
  stage(res, "link:begin", { hasBearer: !!bearer, emailProfileId: !!emailProfileId });
  if (!bearer || !emailProfileId) {
    return deny(res, 403, { ok:false, code:"LINK_REQUIRES_VALID_BEARER" });
  }

  // 1) Aktuellen Besitzstand lesen
  const { data: existing, error: exErr } = await sbAdmin
    .from("wallets")
    .select("address,user_id")
    .eq("address", addressLower)
    .maybeSingle();
  if (exErr) return deny(res, 500, { ok:false, code:"DB_SELECT_ERROR" });

  // a) Wallet gehört schon jemand anderem -> sofort abbrechen
  if (existing?.user_id && existing.user_id !== emailProfileId) {
    return deny(res, 409, {
      ok:false,
      code:"WALLET_ALREADY_LINKED",
      message:"This wallet is already linked to another profile."
    });
  }

  // 2) Optimistisches Upsert – nur übernehmen, wenn (noch) unassigned
  //    Dank UNIQUE(wallets.lower(address)) kein doppeltes Einfügen möglich.
  const { data: up, error: upErr } = await sbAdmin
    .from("wallets")
    .upsert(
      { address: addressLower, user_id: emailProfileId },
      { onConflict: "address", ignoreDuplicates: false }
    )
    .select("user_id")
    .single();

  // 23505 = unique_violation (Race). Danach Besitzstand erneut prüfen:
  if (upErr && String(upErr.code) === "23505") {
    const { data: again } = await sbAdmin
      .from("wallets")
      .select("user_id")
      .eq("address", addressLower)
      .maybeSingle();

    if (!again || (again.user_id && again.user_id !== emailProfileId)) {
      return deny(res, 409, {
        ok:false,
        code:"WALLET_ALREADY_LINKED",
        message:"This wallet is already linked to another profile."
      });
    }
  } else if (upErr) {
    return deny(res, 500, { ok:false, code:"LINK_ERROR" });
  }

  // 3) Sicherheitscheck: falls das Upsert einen fremden user_id ergeben hätte
  if ((up?.user_id ?? existing?.user_id ?? null) !== emailProfileId) {
    return deny(res, 409, { ok:false, code:"WALLET_ALREADY_LINKED" });
  }

  isRegistered = true;
  walletUserId = emailProfileId;
}

    // NORMALER SIGN-IN (kein Link)
    if (intent !== "link") {
      stage(res, "normal:gate", { isRegistered, walletUserId, emailProfileId: !!emailProfileId });
      if (!isRegistered) return deny(res, 403, { ok:false, code:"WALLET_NOT_REGISTERED", message:"No account found for this wallet. Please sign up or link first." });
      if (!walletUserId) return deny(res, 409, { ok:false, code:"WALLET_UNASSIGNED", message:"This wallet is not linked to any profile yet. Use Link mode." });
      if (emailProfileId && walletUserId !== emailProfileId) {
        return deny(res, 409, { ok:false, code:"OTHER_ACCOUNT_ACTIVE", message:"Another account is active via email. Use Link mode." });
      }
    }

    // Session setzen
    stage(res, "session:set");
    const payload = { v: 1, addr: addressLower, userId: walletUserId, ts: Date.now(), exp: Date.now() + SESSION_TTL_SEC * 1000 };
    const raw = JSON.stringify(payload);
    const sig = sign(raw);
    const sessionValue = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");

    clearCookie(res, COOKIE_NONCE);
    setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });

    stage(res, "ok");
    return res.status(200).json({ ok:true, address: addressLower, userId: walletUserId, linked: intent === "link" });
  } catch (e) {
    console.error("[SIWE verify] unexpected error:", e);
    stage(res, "unexpected");
    errHdr(res, e);
    return deny(res, 500, { ok:false, code:"INTERNAL_ERROR" });
  }
}

// ⬅️ GANZ WICHTIG:
export default withCors(handler);
export const config = { runtime: "nodejs" };
