// /api/auth/verify.js  — stabile SIWE-Verify-Route mit Registrierungs-/Link-Option (Node runtime)

import crypto from "node:crypto";

/* ===== Konfiguration ===== */
const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);
const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];
const ALLOWED_CHAINS = new Set([1, 11155111]); // mainnet + sepolia
const MAX_AGE_MIN = 10;
const MAX_SKEW_MS = 5 * 60 * 1000;

const COOKIE_NONCE = "tc_nonce";
const COOKIE_SESSION = "tc_session";
const SESSION_TTL_SEC = 60 * 60 * 24; // 1 Tag

const SESSION_SECRET = process.env.SESSION_SECRET || null;

function setDebug(res, msg) {
  try { res.setHeader("X-TC-Debug", msg); } catch {}
}

/* ===== kleine Helfer ===== */
function originAllowed(origin) {
  try {
    if (!origin) return false;
    const u = new URL(origin);
    return ALLOWED_DOMAINS.has(u.hostname);
  } catch {
    return false;
  }
}
function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`];
  parts.push("Path=/");
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  parts.push("HttpOnly");
  parts.push("SameSite=None");
  parts.push("Secure");
  parts.push("Partitioned");
  const prev = res.getHeader("Set-Cookie");
  const out = [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), parts.join("; ")];
  res.setHeader("Set-Cookie", out);
}
function clearCookie(res, name) {
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure; Partitioned`;
  const prev = res.getHeader("Set-Cookie");
  const out = [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), del];
  res.setHeader("Set-Cookie", out);
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const m = raw.split(/;\s*/).find(s => s.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : null;
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
function parseSiweMessage(msg) {
  const lines = String(msg || "").split("\n");
  if (lines.length < 8) return null;

  const domain  = (lines[0] || "").split(" ")[0] || "";
  const address = (lines[1] || "").trim();

  // ab Zeile 2 die "Key: Value"-Zeilen suchen
  let i = 2;
  while (i < lines.length && !/^[A-Za-z ]+:\s/.test(lines[i])) i++;

  const fields = {};
  for (; i < lines.length; i++) {
    const row = lines[i];
       const idx = row.indexOf(":");
    if (idx === -1) continue;
    const k = row.slice(0, idx).trim().toLowerCase();
    const v = row.slice(idx + 1).trim();
    fields[k] = v;
  }

  const out = {
    domain,
    address,
    uri: fields["uri"],
    version: fields["version"],
    chainId: Number(fields["chain id"]),
    nonce: fields["nonce"],
    issuedAt: fields["issued at"],
  };
  if (!out.domain || !out.address || !out.uri || !out.version || !out.chainId || !out.nonce || !out.issuedAt) {
    return null;
  }
  return out;
}
function readBearer(req) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

/* ===== Handler ===== */
export default async function handler(req, res) {
  const origin = req.headers.origin || "";
  const allowed = originAllowed(origin);

  // --- CORS ---
  res.setHeader("Vary", "Origin");
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-TC-Intent");

  if (req.method === "OPTIONS") {
    setDebug(res, allowed ? "preflight-ok" : "preflight-denied");
    return res.status(204).end();
  }
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  }

  try {
    if (!allowed) {
      setDebug(res, "origin-denied");
      return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED" });
    }

    // Intent + optionaler Supabase-Bearer (für Link-Fall)
    const intent = String(req.headers["x-tc-intent"] || "").toLowerCase(); // "link" | "" (default)
    const bearer = readBearer(req);

    // 1) Payload
    const { message, signature } = req.body || {};
    if (!message || !signature) {
      setDebug(res, "bad-payload");
      return res.status(400).json({ ok: false, code: "INVALID_PAYLOAD" });
    }

    // 2) Server-Nonce
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    if (!cookieNonce) {
      setDebug(res, "missing-nonce");
      return res.status(400).json({ ok: false, code: "MISSING_SERVER_NONCE" });
    }

    // 3) SIWE parse + Checks
    const siwe = parseSiweMessage(message);
    if (!siwe) {
      setDebug(res, "siwe-parse-failed");
      return res.status(400).json({ ok: false, code: "INVALID_SIWE_FORMAT" });
    }
    if (!ALLOWED_DOMAINS.has(siwe.domain)) {
      setDebug(res, "siwe-domain-denied");
      return res.status(400).json({ ok: false, code: "DOMAIN_NOT_ALLOWED" });
    }
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p))) {
        setDebug(res, "siwe-uri-denied");
        return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
      }
    } catch {
      setDebug(res, "siwe-uri-parse-error");
      return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
    }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) {
      setDebug(res, "siwe-chain-denied");
      return res.status(400).json({ ok: false, code: "CHAIN_NOT_ALLOWED" });
    }
    if (!withinAge(siwe.issuedAt)) {
      setDebug(res, "siwe-issuedAt-too-old");
      return res.status(400).json({ ok: false, code: "MESSAGE_TOO_OLD" });
    }
    if (siwe.nonce !== cookieNonce) {
      setDebug(res, "nonce-mismatch");
      return res.status(401).json({ ok: false, code: "NONCE_MISMATCH" });
    }

    // 4) Signatur prüfen
    setDebug(res, "stage:ethers-verify");
    const ethersMod = await import("ethers");
    const verify =
      ethersMod.verifyMessage ||
      (ethersMod.default && ethersMod.default.verifyMessage) ||
      (ethersMod.utils && ethersMod.utils.verifyMessage);
    if (typeof verify !== "function") {
      setDebug(res, "verify-unavailable");
      return res.status(500).json({ ok: false, code: "VERIFY_UNAVAILABLE" });
    }
    const recovered = await verify(message, signature);
    if (!addrEq(recovered, siwe.address)) {
      setDebug(res, "address-mismatch");
      return res.status(401).json({ ok: false, code: "ADDRESS_MISMATCH" });
    }

    // 5) Supabase Admin init
    setDebug(res, "stage:db-init");
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      setDebug(res, "db-env-missing");
      return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
    }
    const { createClient } = await import("@supabase/supabase-js");
    const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

    // 6) Registrierung prüfen
    setDebug(res, "stage:db-check");
    const addressLower = String(siwe.address || "").toLowerCase();
    const { data: isRegistered, error: regErr } = await sbAdmin.rpc("wallet_registered", { p_address: addressLower });
    if (regErr) {
      console.error("[SIWE] wallet_registered rpc error:", regErr);
      setDebug(res, "db-rpc-error");
      return res.status(500).json({ ok: false, code: "DB_RPC_ERROR" });
    }

    let userId = null;

    // 6a) OPTIONALER LINK-FALL: Wallet noch nicht registriert, aber wir dürfen linken
    if (!isRegistered && intent === "link" && bearer) {
      setDebug(res, "stage:link-mode");

      // Auth-User aus Bearer ermitteln
      const { data: authData, error: authErr } = await sbAdmin.auth.getUser(bearer);
      if (authErr || !authData?.user?.id) {
        setDebug(res, "link-auth-invalid");
        return res.status(403).json({ ok: false, code: "LINK_REQUIRES_VALID_BEARER" });
      }
      const authUserId = authData.user.id;

      // Profil zu diesem E-Mail-User finden/erzeugen
      let linkProfileId = null;
      const { data: existingProfile } = await sbAdmin
        .from("profiles").select("id").eq("user_id", authUserId).maybeSingle();
      if (existingProfile?.id) {
        linkProfileId = existingProfile.id;
      } else {
        const { data: profNew, error: pErr } = await sbAdmin
          .from("profiles").insert({ user_id: authUserId }).select("id").single();
        if (pErr) {
          console.error("[verify:link] create profile failed:", pErr);
          return res.status(500).json({ ok: false, code: "PROFILE_CREATE_ERROR" });
        }
        linkProfileId = profNew.id;
      }

      // Wallet upsert (falls noch nicht vorhanden)
      const { error: upErr } = await sbAdmin
        .from("wallets").upsert({ address: addressLower }, { onConflict: "address" });
      if (upErr) {
        console.error("[verify:link] wallets upsert failed:", upErr);
        return res.status(500).json({ ok: false, code: "DB_UPSERT_ERROR" });
      }

      // Wallet-Row ziehen
      const { data: walletRow, error: wErr } = await sbAdmin
        .from("wallets").select("user_id").eq("address", addressLower).maybeSingle();
      if (wErr) {
        console.error("[verify:link] wallets select failed:", wErr);
        return res.status(500).json({ ok: false, code: "DB_SELECT_ERROR" });
      }

      // Konflikt, falls schon an anderes Profil gebunden
      if (walletRow?.user_id && walletRow.user_id !== linkProfileId) {
        return res.status(409).json({
          ok: false,
          code: "WALLET_ALREADY_LINKED",
          message: "This wallet is already linked to another profile.",
        });
      }

      // Verlinken
      if (!walletRow?.user_id) {
        const { error: linkErr } = await sbAdmin
          .from("wallets").update({ user_id: linkProfileId }).eq("address", addressLower);
        if (linkErr) {
          console.error("[verify:link] link wallet->profile failed:", linkErr);
          return res.status(500).json({ ok: false, code: "LINK_ERROR" });
        }
      }

      userId = linkProfileId; // für Session
    }

    // 6b) Wenn weiterhin nicht registriert (kein Link-Fall) -> Client soll /register nutzen
    if (!isRegistered && !userId) {
      setDebug(res, "wallet-not-registered");
      return res.status(403).json({
        ok: false,
        code: "WALLET_NOT_REGISTERED",
        message: "No account found for this wallet. Please sign up first.",
      });
    }

    // 7) user_id lookup (Falls registriert war; im Link-Fall oben bereits gesetzt)
    if (!userId) {
      try {
        const { data: row } = await sbAdmin
          .from("wallets").select("user_id").eq("address", addressLower).maybeSingle();
        userId = row?.user_id ?? null;
      } catch (e) {
        console.warn("[SIWE] wallets lookup failed:", e);
      }
    }

    // 8) Session setzen
    setDebug(res, "stage:set-session");
    const payload = {
      v: 1,
      addr: addressLower,
      userId,
      ts: Date.now(),
      exp: Date.now() + SESSION_TTL_SEC * 1000,
    };
    const raw = JSON.stringify(payload);
    const sig = sign(raw);
    const sessionValue = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");

    clearCookie(res, COOKIE_NONCE); // Nonce verbraucht
    setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });

    setDebug(res, "ok");
    return res.status(200).json({ ok: true, address: addressLower, userId, linked: intent === "link" });
  } catch (e) {
    console.error("[SIWE verify] unexpected error:", e);
    setDebug(res, "unexpected");
    return res.status(500).json({ ok: false, code: "INTERNAL_ERROR" });
  }
}

// Nicht als Edge laufen lassen
export const config = { runtime: "nodejs" };
