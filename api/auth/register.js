// api/auth/register.js
// Minimalinvasives, aber vollständiges Register-Endpoint:
// - CORS wie bisher über helpers/cors.js
// - prüft SIWE-Message + Signatur
// - matched Nonce-Cookie (tc_nonce)
// - upsert in `wallets` (address lowercased)
// - optionales Setzen von creatorName in profiles (falls vorhanden)
// - invalidiert Nonce-Cookie

import { withCors } from "../../helpers/cors.js";

/* ---- lokale, selbstständige Helfer (kein TS-Import nötig) ---- */
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

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const hit = raw.split(/;\s*/).find((s) => s.startsWith(name + "="));
  return hit ? decodeURIComponent(hit.split("=").slice(1).join("=")) : null;
}

function clearCookie(res, name) {
  const del =
    `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure; Partitioned`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader(
    "Set-Cookie",
    [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), del]
  );
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

// sehr robuste, generische SIWE-Parser-Funktion (passt zu deinem verify.js)
function parseSiweMessage(msg) {
  const lines = String(msg || "").split("\n");
  if (lines.length < 2) return null;

  const domain = (lines[0] || "").split(" ")[0] || "";
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

  if (
    !out.domain ||
    !out.address ||
    !out.uri ||
    !out.version ||
    !out.chainId ||
    !out.nonce ||
    !out.issuedAt
  ) {
    return null;
  }
  return out;
}

/* ---- Handler ---- */
async function handler(req, res) {
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  }

  // 1) Origin-Whitelist (nach Preflight)
  const origin = req.headers.origin || "";
  try {
    const host = origin ? new URL(origin).hostname : "";
    if (!host || !ALLOWED_DOMAINS.has(host)) {
      return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED" });
    }
  } catch {
    return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED" });
  }

  // 2) Body lesen
  let body = req.body;
  if (body == null || typeof body !== "object") {
    try {
      body = JSON.parse(req.body || "{}");
    } catch {
      body = {};
    }
  }
  const message = body?.message;
  const signature = body?.signature;
  const creatorName = body?.creatorName ?? null;

  if (!message || !signature) {
    return res
      .status(400)
      .json({ ok: false, code: "INVALID_PAYLOAD", message: "Missing message or signature" });
  }

  // 3) Server-Nonce muss vorhanden sein (CHIPS-Cookie von /nonce)
  const cookieNonce = getCookie(req, COOKIE_NONCE);
  if (!cookieNonce) {
    return res.status(400).json({ ok: false, code: "MISSING_SERVER_NONCE" });
  }

  // 4) SIWE-Message parsen + Grundchecks
  const siwe = parseSiweMessage(message);
  if (!siwe) return res.status(400).json({ ok: false, code: "INVALID_SIWE_FORMAT" });

  if (!ALLOWED_DOMAINS.has(siwe.domain)) {
    return res.status(400).json({ ok: false, code: "DOMAIN_NOT_ALLOWED" });
  }
  try {
    const u = new URL(siwe.uri);
    if (!ALLOWED_URI_PREFIXES.some((p) => u.href.startsWith(p))) {
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
  if (siwe.nonce !== cookieNonce) {
    return res.status(401).json({ ok: false, code: "NONCE_MISMATCH" });
  }

  // 5) Signatur verifizieren (ethers lazy import – gleiche Logik wie verify.js)
  const ethersMod = await import("ethers");
  const verify =
    ethersMod.verifyMessage ||
    (ethersMod.default && ethersMod.default.verifyMessage) ||
    (ethersMod.utils && ethersMod.utils.verifyMessage);

  if (typeof verify !== "function") {
    return res.status(500).json({ ok: false, code: "VERIFY_UNAVAILABLE" });
  }

  const recovered = await verify(message, signature);
  if (!addrEq(recovered, siwe.address)) {
    return res.status(401).json({ ok: false, code: "ADDRESS_MISMATCH" });
  }

  // 6) Supabase Admin (Service Role) – Wallet registrieren
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
  }

  const { createClient } = await import("@supabase/supabase-js");
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  const addressLower = String(siwe.address).toLowerCase();

  // Upsert in wallets (erfüllt anschließend wallet_registered() für /verify)
  const { error: upErr } = await sb
    .from("wallets")
    .upsert({ address: addressLower }, { onConflict: "address" });

  if (upErr) {
    console.error("[register] upsert wallets failed:", upErr);
    return res.status(500).json({ ok: false, code: "DB_UPSERT_ERROR" });
  }

  // Optional: creator_name in profiles setzen, falls schema vorhanden
  if (creatorName && String(creatorName).trim()) {
    try {
      const { data: link } = await sb
        .from("wallets")
        .select("user_id")
        .eq("address", addressLower)
        .maybeSingle();

      if (link?.user_id) {
        await sb
          .from("profiles")
          .update({ creator_name: String(creatorName).trim() })
          .eq("id", link.user_id);
      }
    } catch (e) {
      console.warn("[register] optional profile update skipped:", e?.message || e);
    }
  }

  // 7) Nonce ist single-use → löschen
  clearCookie(res, COOKIE_NONCE);

  return res.status(200).json({ ok: true, registered: true });
}

export default withCors(handler);
