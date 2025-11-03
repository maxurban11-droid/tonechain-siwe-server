// /api/auth/link-wallet.js — verknüpft eine verifizierte SIWE-Adresse mit dem
// aktuell eingeloggten Supabase-User (Email-Session).
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

/* — optional dieselben Limits wie in verify.js — */
const ALLOWED_DOMAINS = new Set(["tonechain.app","concave-device-193297.framer.app"]);
const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];
const ALLOWED_CHAINS = new Set([1, 11155111]);
const MAX_AGE_MIN = 10;
const MAX_SKEW_MS = 5 * 60 * 1000;

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

export default async function handler(req, res) {
  // CORS
  const origin = req.headers.origin || "*";
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });

  // ENV → Supabase Admin
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
  }
  const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

  // 1) Supabase-User aus Authorization: Bearer <access_token>
  const authz = req.headers.authorization || "";
  const token = authz.toLowerCase().startsWith("bearer ") ? authz.slice(7).trim() : "";
  if (!token) return res.status(401).json({ ok: false, code: "NO_SUPABASE_TOKEN" });

  let userId;
  try {
    const { data, error } = await sbAdmin.auth.getUser(token);
    if (error || !data?.user?.id) throw error || new Error("No user");
    userId = data.user.id;
  } catch (e) {
    return res.status(401).json({ ok: false, code: "INVALID_SUPABASE_TOKEN" });
  }

  // 2) Payload (SIWE message + signature)
  let body = {};
  try { body = req.body || {}; } catch {}
  const { message, signature } = body;
  if (!message || !signature) {
    return res.status(400).json({ ok: false, code: "INVALID_PAYLOAD" });
  }

  // 3) SIWE verifizieren (ohne Nonce-Cookie-Pflicht, da dies hier *Linking* ist)
  const siwe = parseSiweMessage(message);
  if (!siwe) return res.status(400).json({ ok: false, code: "INVALID_SIWE_FORMAT" });

  if (!ALLOWED_DOMAINS.has(siwe.domain)) return res.status(400).json({ ok: false, code: "DOMAIN_NOT_ALLOWED" });
  try {
    const u = new URL(siwe.uri);
    if (!ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p))) {
      return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
    }
  } catch {
    return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
  }
  if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) {
    return res.status(400).json({ ok: false, code: "CHAIN_NOT_ALLOWED" });
  }
  if (!withinAge(siwe.issuedAt)) {
    return res.status(400).json({ ok: false, code: "MESSAGE_TOO_OLD" });
  }

  // ethers.verifyMessage (dynamisch)
  let recovered;
  try {
    const mod = await import("ethers");
    const verify =
      mod.verifyMessage ||
      (mod.default && mod.default.verifyMessage) ||
      (mod.utils && mod.utils.verifyMessage);
    recovered = await verify(message, signature);
  } catch (e) {
    return res.status(400).json({ ok: false, code: "SIGNATURE_VERIFY_FAILED" });
  }
  if (!addrEq(recovered, siwe.address)) {
    return res.status(401).json({ ok: false, code: "ADDRESS_MISMATCH" });
  }

  const addressLower = siwe.address.toLowerCase();

  // 4) Prüfen, ob diese Wallet schon existiert (doppelte vermeiden)
  try {
    const { data: rows, error } = await sbAdmin
      .from("wallets")
      .select("id, user_id")
      .eq("address", addressLower)
      .limit(1);
    if (error) throw error;
    if ((rows?.length ?? 0) > 0) {
      // Falls bereits mit einem (anderen) User verknüpft → ablehnen
      if (rows[0].user_id !== userId) {
        return res.status(409).json({ ok: false, code: "WALLET_ALREADY_LINKED" });
      }
      // schon verknüpft mit diesem User → ok
      return res.status(200).json({ ok: true, linked: true, already: true });
    }
  } catch (e) {
    console.error("[link-wallet] select error:", e);
    return res.status(500).json({ ok: false, code: "DB_ERROR" });
  }

  // 5) Primary-Flag entscheiden
  let makePrimary = false;
  try {
    const { data: countRows, error: cntErr } = await sbAdmin
      .from("wallets")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId);
    if (cntErr) throw cntErr;
    // wenn der User noch keine Wallet hat → die neue wird primary
    makePrimary = (countRows === null); // head:true → data = null; count via header
  } catch (e) {
    console.warn("[link-wallet] primary check warn:", e);
  }

  // 6) Insert
  try {
    const { error } = await sbAdmin.from("wallets").insert({
      user_id: userId,
      address: addressLower,
      is_primary: !!makePrimary,
    });
    if (error) throw error;
    return res.status(200).json({ ok: true, linked: true, is_primary: !!makePrimary });
  } catch (e) {
    console.error("[link-wallet] insert error:", e);
    // Unique-Constraints greifen hier ggf. zusätzlich
    return res.status(500).json({ ok: false, code: "DB_INSERT_ERROR" });
  }
}
