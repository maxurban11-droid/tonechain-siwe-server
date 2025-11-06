// /api/auth/verify.js — SIWE-Verify mit Link-Option & striktem Doppelkonto-Schutz (Node runtime)
import crypto from "node:crypto";
import { readNonceFromReq } from "../../helpers/nonce.js";
import { SiweMessage } from "siwe"; // falls du SIWE parse nutzt

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

const provided = readNonceFromReq(req);        // Header oder Cookie
const { message, signature } = req.body || {};
const msg = new SiweMessage(message);
const fields = await msg.verify({ signature, /* ... */ });
// Prüfen, dass Nonce in der Message = bereitgestellte Nonce:
if (!provided || String(fields.data.nonce) !== String(provided)) {
  return res.status(400).json({ ok:false, code:"NONCE_MISMATCH" });
}

function setDebug(res, msg) {
  try { res.setHeader("X-TC-Debug", msg); } catch {}
}

/* ===== Helpers ===== */
function originAllowed(origin) {
  try {
    if (!origin) return false;
    const { hostname } = new URL(origin);
    if (ALLOWED_DOMAINS.has(hostname)) return true;
    if (hostname.endsWith(".framer.app") || hostname.endsWith(".framer.website")) return true;
    if (hostname === "localhost" || hostname === "127.0.0.1") return true;
    return false;
  } catch { return false; }
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

// Einheitliche Ablehnung: sorgt IMMER dafür, dass alte Cookies entfernt werden.
function deny(res, status, body) {
  try {
    clearCookie(res, COOKIE_SESSION);
    clearCookie(res, COOKIE_NONCE);
  } catch {}
  return res.status(status).json(body);
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

  // Key: Value-Zeilen
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
  if (!out.domain || !out.address || !out.uri || !out.version || !out.chainId || !out.nonce || !out.issuedAt) return null;
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
  // beide Schreibweisen zulassen
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-TC-Intent, x-tc-intent");

  if (req.method === "OPTIONS") {
    setDebug(res, allowed ? "preflight-ok" : "preflight-denied");
    return res.status(204).end();
  }
  if (req.method !== "POST") return deny(res, 405, { ok: false, code: "METHOD_NOT_ALLOWED" });
  if (!allowed) return deny(res, 403, { ok: false, code: "ORIGIN_NOT_ALLOWED" });

  try {
    const intent = String(req.headers["x-tc-intent"] || req.headers["X-TC-Intent"] || "").toLowerCase(); // "link" | ""
    const bearer = readBearer(req);

    // 1) Payload
    const { message, signature } = req.body || {};
    if (!message || !signature) return deny(res, 400, { ok: false, code: "INVALID_PAYLOAD" });

    // 2) Server-Nonce
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    if (!cookieNonce) return deny(res, 400, { ok: false, code: "MISSING_SERVER_NONCE" });

    // 3) SIWE parse + Checks
    const siwe = parseSiweMessage(message);
    if (!siwe) return deny(res, 400, { ok: false, code: "INVALID_SIWE_FORMAT" });
    if (!ALLOWED_DOMAINS.has(siwe.domain)) return deny(res, 400, { ok: false, code: "DOMAIN_NOT_ALLOWED" });
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p))) return deny(res, 400, { ok: false, code: "URI_NOT_ALLOWED" });
    } catch { return deny(res, 400, { ok: false, code: "URI_NOT_ALLOWED" }); }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return deny(res, 400, { ok: false, code: "CHAIN_NOT_ALLOWED" });
    if (!withinAge(siwe.issuedAt)) return deny(res, 400, { ok: false, code: "MESSAGE_TOO_OLD" });
    if (siwe.nonce !== cookieNonce) return deny(res, 401, { ok: false, code: "NONCE_MISMATCH" });

    // 4) Signatur prüfen
    setDebug(res, "stage:ethers-verify");
    const ethersMod = await import("ethers");
    const verify =
      ethersMod.verifyMessage ||
      (ethersMod.default && ethersMod.default.verifyMessage) ||
      (ethersMod.utils && ethersMod.utils.verifyMessage);
    if (typeof verify !== "function") return deny(res, 500, { ok: false, code: "VERIFY_UNAVAILABLE" });

    const recovered = await verify(message, signature);
    if (!addrEq(recovered, siwe.address)) return deny(res, 401, { ok: false, code: "ADDRESS_MISMATCH" });

    // 5) Supabase Admin
    setDebug(res, "stage:db-init");
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return deny(res, 500, { ok: false, code: "SERVER_CONFIG_MISSING" });
    const { createClient } = await import("@supabase/supabase-js");
    const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

    // 6) Wallet-Registrierung & Zuordnung
    setDebug(res, "stage:db-check");
    const addressLower = String(siwe.address || "").toLowerCase();
    const { data: walletRow, error: wErr } = await sbAdmin
      .from("wallets")
      .select("address,user_id")
      .eq("address", addressLower)
      .maybeSingle();
    if (wErr) return deny(res, 500, { ok: false, code: "DB_SELECT_ERROR" });

    let isRegistered = !!walletRow;
    let walletUserId = walletRow?.user_id ?? null;

    // Aktives E-Mail-Profil bestimmen (falls Bearer vorhanden)
    let emailProfileId = null;
    if (bearer) {
      const { data: authData, error: authErr } = await sbAdmin.auth.getUser(bearer);
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
    }

    /* ===== LINK-MODUS ===== */
    if (intent === "link") {
      if (!bearer || !emailProfileId) {
        return deny(res, 403, { ok: false, code: "LINK_REQUIRES_VALID_BEARER" });
      }

      // Wallet gehört bereits einem ANDEREN Profil → block
      if (walletUserId && walletUserId !== emailProfileId) {
        return deny(res, 409, {
          ok: false,
          code: "WALLET_ALREADY_LINKED",
          message: "This wallet is already linked to another profile.",
        });
      }

      // 6a) Versuch: atomisch per RPC (falls vorhanden)
      let linked = false;
      try {
        const { error: rpcErr } = await sbAdmin.rpc("link_wallet_to_profile", {
          p_address: addressLower,
          p_profile_id: emailProfileId,
        });
        if (rpcErr) {
          const msg = (rpcErr.message || "").toLowerCase();
          if (msg.includes("wallet_already_linked")) {
            return deny(res, 409, {
              ok: false,
              code: "WALLET_ALREADY_LINKED",
              message: "This wallet is already linked to another profile.",
            });
          }
          // Wenn die Funktion nicht existiert, fällt es in den Fallback unten
          if (!msg.includes("function") && !msg.includes("procedure")) {
            // echter Fehler
            console.error("[verify:link] RPC failed:", rpcErr);
            return deny(res, 500, { ok: false, code: "DB_LINK_RPC_ERROR" });
          }
        } else {
          linked = true;
        }
      } catch {
        // ignorieren → Fallback
      }

      // 6b) Fallback ohne RPC: sicherer 2-Phasen-Flow ohne Fremdüberschreibung
      if (!linked) {
        if (!isRegistered) {
          // Insert versuchen
          const { error: insErr } = await sbAdmin
            .from("wallets")
            .insert({ address: addressLower, user_id: emailProfileId });
          if (insErr) {
            // Kann Konflikt sein (unique address) -> reselect und prüfen
            const { data: again } = await sbAdmin
              .from("wallets")
              .select("address,user_id")
              .eq("address", addressLower)
              .maybeSingle();
            const uid = again?.user_id ?? null;
            if (uid && uid !== emailProfileId) {
              return deny(res, 409, {
                ok: false,
                code: "WALLET_ALREADY_LINKED",
                message: "This wallet is already linked to another profile.",
              });
            }
            if (!uid) {
              return deny(res, 500, { ok: false, code: "DB_UPSERT_ERROR" });
            }
          }
          isRegistered = true;
          walletUserId = emailProfileId;
        } else if (!walletUserId) {
          // Nur verlinken, wenn derzeit unclaimed
          const { data: upd, error: linkErr } = await sbAdmin
            .from("wallets")
            .update({ user_id: emailProfileId })
            .eq("address", addressLower)
            .is("user_id", null)
            .select("user_id"); // damit wir sehen, ob was passiert ist
          if (linkErr) {
            return deny(res, 500, { ok: false, code: "LINK_ERROR" });
          }
          // Wenn nichts updatet wurde, prüfen ob inzw. jemand anders verlinkt hat
          if (!upd || upd.length === 0) {
            const { data: again } = await sbAdmin
              .from("wallets")
              .select("address,user_id")
              .eq("address", addressLower)
              .maybeSingle();
            const uid = again?.user_id ?? null;
            if (uid && uid !== emailProfileId) {
              return deny(res, 409, {
                ok: false,
                code: "WALLET_ALREADY_LINKED",
                message: "This wallet is already linked to another profile.",
              });
            }
            if (!uid) {
              return deny(res, 500, { ok: false, code: "LINK_ERROR" });
            }
          }
          walletUserId = emailProfileId;
        } else {
          // walletUserId === emailProfileId → idempotent OK
        }
      }
      // -> fällt unten in die Session-Setzung
    }

    /* ===== NORMALER MODUS (kein link) ===== */
    if (intent !== "link") {
      // Wallet existiert nicht → block (Sign-up/Link zuerst)
      if (!isRegistered) {
        return deny(res, 403, {
          ok: false,
          code: "WALLET_NOT_REGISTERED",
          message: "No account found for this wallet. Please sign up or link first.",
        });
      }
      // Wallet existiert, aber ohne Zuordnung → block (nur Link-Modus darf verknüpfen)
      if (!walletUserId) {
        return deny(res, 409, {
          ok: false,
          code: "WALLET_UNASSIGNED",
          message: "This wallet is not linked to any profile yet. Use Link mode.",
        });
      }
      // Falls eine E-Mail-Session aktiv ist, muss sie mit der Wallet übereinstimmen
      if (emailProfileId && walletUserId !== emailProfileId) {
        return deny(res, 409, {
          ok: false,
          code: "OTHER_ACCOUNT_ACTIVE",
          message: "Another account is active via email. Use Link mode.",
        });
      }
    }

    // 7) user_id final bestimmen
    let userId = walletUserId ?? null;
    if (!userId && isRegistered) {
      const { data: row2 } = await sbAdmin
        .from("wallets")
        .select("user_id")
        .eq("address", addressLower)
        .maybeSingle();
      userId = row2?.user_id ?? null;
    }

    // Sicherheitsnetz: OHNE userId KEINE Session
    if (!userId) {
      return deny(res, 403, {
        ok: false,
        code: "NO_USER_FOR_WALLET",
        message: "Wallet has no associated user. Link required.",
      });
    }

    // 8) SIWE-Session Cookie setzen (nur jetzt, da userId valide)
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
    return res.status(200).json({
      ok: true,
      address: addressLower,
      userId,
      linked: intent === "link",
    });
  } catch (e) {
    console.error("[SIWE verify] unexpected error:", e);
    setDebug(res, "unexpected");
    return deny(res, 500, { ok: false, code: "INTERNAL_ERROR" });
  }
}

export const config = { runtime: "nodejs" };
