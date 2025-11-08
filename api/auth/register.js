// api/auth/register.js
// SIWE "register/signup" + "link" – robustes CORS, raw-body, Debug-Stages, Node runtime.

import { withCors } from "../../helpers/cors.js";
import { createClient } from '@supabase/supabase-js'

/* ---------- Policy ---------- */
const ALLOWED_DOMAINS = new Set(["tonechain.app", "concave-device-193297.framer.app"]);
const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];
const ALLOWED_CHAINS = new Set([1, 11155111]); // mainnet + sepolia
const MAX_AGE_MIN = 10;
const MAX_SKEW_MS = 5 * 60 * 1000;
const COOKIE_NONCE = "tc_nonce";

/* ---------- Debug-Helper ---------- */
const DEBUG_SIWE = process.env.DEBUG_SIWE === "1";
function setHdr(res, k, v) { try { res.setHeader(k, v); } catch {} }
function stage(res, label, extra) {
  setHdr(res, "X-TC-Debug", label);
  if (DEBUG_SIWE && extra !== undefined) {
    console.log("[register]", label, typeof extra === "object" ? JSON.stringify(extra) : String(extra));
  }
}
function errHdr(res, e) {
  const msg = (e && (e.body || e.message)) ? String(e.body || e.message) : String(e);
  setHdr(res, "X-TC-Error", msg.slice(0, 240));
}

/* ---------- Helpers ---------- */
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const hit = raw.split(/;\s*/).find((s) => s.startsWith(name + "="));
  if (!hit) return null;
  const val = hit.split("=").slice(1).join("=");
  try { return decodeURIComponent(val); } catch { return val; }
}
function withinAge(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  const age = Math.abs(Date.now() - t);
  return age <= MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS;
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
// Raw-Body robust lesen (kein req.body verwenden!)
async function readJsonBody(req) {
  try {
    let raw = "";
    for await (const chunk of req) {
      raw += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    }
    if (!raw) return {};
    try { return JSON.parse(raw); } catch { return {}; }
  } catch { return {}; }
}
// toleranter SIWE-Parser (case-insensitiv, CRLF/LF tolerant)
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
  if (chainRaw != null) { const num = chainRaw.match(/(\d+)/); if (num) chainId = Number(num[1]); }
  if (!domain || !address || !uri || !version || !chainId || !nonce || !issuedAt) return null;
  return { domain, address, uri, version, chainId, nonce, issuedAt };
}

/* ---------- Handler ---------- */
async function handler(req, res) {
  setHdr(res, "Access-Control-Expose-Headers", "X-TC-Debug, X-TC-Error, X-TC-CT, X-TC-Nonce-Source");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });

  try {
    const intent = String(req.headers["x-tc-intent"] || req.headers["X-TC-Intent"] || "").toLowerCase(); // "signup" | "link"
    const bearer = readBearer(req);
    stage(res, "recv", { intent, hasBearer: !!bearer });
    setHdr(res, "X-TC-CT", String(req.headers["content-type"] || ""));

    // Body robust einlesen
    stage(res, "parse-body:raw");
    const body = await readJsonBody(req);
    let message = body?.message;
    const signature = body?.signature;
    const creatorName = (body?.creatorName ?? "").toString().trim();

    if (typeof message === "string") {
      if (message.indexOf("\\n") !== -1 && message.indexOf("\n") === -1) message = message.replace(/\\n/g, "\n");
      message = message.replace(/\r\n/g, "\n").replace(/^\uFEFF/, "");
    }
    if (!message || !signature) {
      return res.status(400).json({ ok: false, code: "INVALID_PAYLOAD", message: "Missing message or signature" });
    }
    if (intent === "signup" && !creatorName) {
      return res.status(400).json({ ok:false, code:"CREATOR_NAME_REQUIRED", message:"Creator name is required for signup" });
    }

    // Nonce
    stage(res, "nonce:get");
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    const headerNonce = (req.headers["x-tc-nonce"] ? String(req.headers["x-tc-nonce"]) : "").trim() || null;
    const serverNonce = cookieNonce || headerNonce;
    setHdr(res, "X-TC-Nonce-Source", cookieNonce ? "cookie" : (headerNonce ? "header" : "none"));
    if (!serverNonce) return res.status(400).json({ ok: false, code: "MISSING_SERVER_NONCE" });

    // SIWE prüfen
    stage(res, "siwe:parse");
    const siwe = parseSiweMessage(String(message));
    if (!siwe) return res.status(400).json({ ok: false, code: "INVALID_SIWE_FORMAT" });
    if (!ALLOWED_DOMAINS.has(siwe.domain)) return res.status(400).json({ ok: false, code: "DOMAIN_NOT_ALLOWED" });
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some((p) => u.href.startsWith(p))) {
        return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
      }
    } catch { return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" }); }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return res.status(400).json({ ok: false, code: "CHAIN_NOT_ALLOWED" });
    if (!withinAge(siwe.issuedAt)) return res.status(400).json({ ok: false, code: "MESSAGE_TOO_OLD" });
    if (siwe.nonce !== serverNonce) return res.status(401).json({ ok: false, code: "NONCE_MISMATCH" });

    // Signatur prüfen
    stage(res, "ethers:verify");
    const ethersMod = await import("ethers");
    const verify =
      ethersMod.verifyMessage ||
      (ethersMod.default && ethersMod.default.verifyMessage) ||
      (ethersMod.utils && ethersMod.utils.verifyMessage);
    if (typeof verify !== "function") return res.status(500).json({ ok: false, code: "VERIFY_UNAVAILABLE" });

    const recovered = await verify(String(message), String(signature));
    if (!addrEq(recovered, siwe.address)) return res.status(401).json({ ok: false, code: "ADDRESS_MISMATCH" });

    // Supabase Admin
    stage(res, "db:init");
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
    }
    const { createClient } = await import("@supabase/supabase-js");
    const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

    const addressLower = String(siwe.address || "").toLowerCase();

    /* ---- 1) Wallet-Row sicherstellen (unique by address) ---- */
    stage(res, "db:wallet-upsert");
    {
      const { error: upErr } = await sb
        .from("wallets")
        .upsert({ address: addressLower }, { onConflict: "address" });
      if (upErr) {
        console.error("[register] upsert wallets failed:", upErr);
        return res.status(500).json({ ok: false, code: "DB_UPSERT_ERROR" });
      }
    }

    // Aktuellen Wallet-Status lesen
    stage(res, "db:wallet-select");
    let { data: walletRow, error: wErr } = await sb
      .from("wallets")
      .select("address,user_id")
      .eq("address", addressLower)
      .maybeSingle();
    if (wErr) {
      console.error("[register] select wallets failed:", wErr);
      return res.status(500).json({ ok: false, code: "DB_SELECT_ERROR" });
    }
    let profileId = walletRow?.user_id ?? null;

    /* ---- 2) LINK: bestehende E-Mail-Session per Bearer verknüpfen ---- */
    let authUserId = null;
    let linkProfileId = null;

    if (intent === "link") {
      stage(res, "link:begin", { hasBearer: !!bearer });
      if (!bearer) return res.status(403).json({ ok: false, code: "LINK_REQUIRES_VALID_BEARER" });

      try {
        const { data: authData, error: authErr } = await sb.auth.getUser(bearer);
        if (!authErr) authUserId = authData?.user?.id || null;
      } catch (e) {
        console.warn("[register] getUser via bearer exception:", e?.message || e);
      }
      if (!authUserId) {
        return res.status(403).json({ ok: false, code: "LINK_REQUIRES_VALID_BEARER" });
      }

      // Profil der E-Mail-Session holen/erstellen
      const { data: profExisting } = await sb
        .from("profiles")
        .select("id")
        .eq("user_id", authUserId)
        .maybeSingle();

      if (profExisting?.id) {
        linkProfileId = profExisting.id;
      } else {
        const { data: profNew, error: pInsErr } = await sb
          .from("profiles")
          .insert({ user_id: authUserId, ...(creatorName ? { creator_name: creatorName } : {}) })
          .select("id")
          .single();
        if (pInsErr) {
          console.error("[register] create profiles(user_id=auth) failed:", pInsErr);
          return res.status(500).json({ ok: false, code: "PROFILE_CREATE_ERROR" });
        }
        linkProfileId = profNew.id;
      }

      // Wallet gehört schon jemand anderem?
      if (walletRow?.user_id && walletRow.user_id !== linkProfileId) {
        return res.status(409).json({ ok: false, code: "WALLET_ALREADY_LINKED", message: "This wallet is already linked to another profile." });
      }

      // Wallet -> aktuelles Profil verlinken (nur wenn noch frei)
      if (!walletRow?.user_id) {
        const { data: upd, error: linkErr } = await sb
          .from("wallets")
          .update({ user_id: linkProfileId })
          .eq("address", addressLower)
          .is("user_id", null)
          .select("user_id");
        if (linkErr) {
          console.error("[register] link wallet->profile failed:", linkErr);
          return res.status(500).json({ ok: false, code: "LINK_ERROR" });
        }
        if (!upd || upd.length === 0) {
          const { data: again } = await sb.from("wallets").select("user_id").eq("address", addressLower).maybeSingle();
          if (!again?.user_id) return res.status(409).json({ ok: false, code: "LINK_RACE_CONFLICT" });
          profileId = again.user_id;
        } else {
          profileId = upd[0]?.user_id ?? linkProfileId;
        }
        walletRow = { ...walletRow, user_id: profileId };
      } else {
        profileId = walletRow.user_id;
      }
    }

    /* ---- 3) SIGNUP: neues Profil nur dann erzeugen, wenn Wallet noch keiner hat ---- */
    if (intent !== "link") {
      stage(res, "signup:begin");
      if (profileId) {
        setHdr(res, "Cache-Control", "no-store");
        return res.status(200).json({
          ok: true,
          registered: true,
          already: true,
          address: addressLower,
          userId: profileId,
          keepNonce: true,
          linked: false,
        });
      }

      // Profil erzeugen (ohne user_id; E-Mail ggf. separat)
      const insertPayload = creatorName ? { creator_name: creatorName } : {};
      const { data: prof, error: pErr } = await sb
        .from("profiles")
        .insert(insertPayload)
        .select("id")
        .single();
      if (pErr) {
        console.error("[register] create profile failed:", pErr);
        return res.status(500).json({ ok: false, code: "PROFILE_CREATE_ERROR" });
      }

      // Wallet atomar „claimen“ (nur wenn noch frei)
      const { data: upd, error: linkErr } = await sb
        .from("wallets")
        .update({ user_id: prof.id })
        .eq("address", addressLower)
        .is("user_id", null)
        .select("user_id");
      if (linkErr) {
        console.error("[register] link wallet->profile failed:", linkErr);
        return res.status(500).json({ ok: false, code: "LINK_ERROR" });
      }
      if (!upd || upd.length === 0) {
        // Lost race → neu erzeugtes Profil aufräumen
        // FIX: QueryBuilder nicht mit .catch ketten – in try/catch kapseln
        try { await sb.from("profiles").delete().eq("id", prof.id); } catch {}
        const { data: again } = await sb.from("wallets").select("user_id").eq("address", addressLower).maybeSingle();
        if (!again?.user_id) {
          return res.status(409).json({ ok: false, code: "SIGNUP_RACE_CONFLICT" });
        }
        profileId = again.user_id;
      } else {
        profileId = upd[0]?.user_id ?? prof.id;
      }
    }

    // Optional: Creator-Name nachtragen
    if (creatorName && profileId) {
      // FIX: kein .catch an Builder; sauber awaiten + Fehler nur loggen
      try {
        const { error: updErr } = await sb
          .from("profiles")
          .update({ creator_name: creatorName })
          .eq("id", profileId)
          .select("id"); // force request
        if (updErr) console.warn("[register] optional set creator_name failed:", updErr);
      } catch (e) {
        console.warn("[register] optional set creator_name exception:", e?.message || e);
      }
    }

    setHdr(res, "Cache-Control", "no-store");
    stage(res, "ok");
    return res.status(200).json({
      ok: true,
      registered: true,
      address: addressLower,
      userId: profileId,
      keepNonce: true,  // wichtig: Verify darf danach sofort erneut erfolgen
      linked: intent === "link",
    });
  } catch (e) {
    console.error("[SIWE register] unexpected error:", e);
    stage(res, "unexpected");
    errHdr(res, e);
    return res.status(500).json({ ok: false, code: "INTERNAL_ERROR" });
  }
}

export default withCors(handler);
export const config = { runtime: "nodejs" };
