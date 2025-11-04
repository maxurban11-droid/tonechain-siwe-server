// api/auth/register.js
// Register-Endpoint (signup): verifiziert SIWE, legt Wallet an,
// sorgt dafür, dass ein gültiger tc_nonce-Cookie für den anschließenden verify()-Call vorhanden ist.

import { withCors } from "../../helpers/cors.js";

/* ---- lokale Helfer & Konstanten ---- */
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
function pushSetCookie(res, cookie) {
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", [cookie]);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie]);
  else res.setHeader("Set-Cookie", [String(prev), cookie]);
}
function setNonceCookie(res, nonce, maxAgeSec = 600) {
  // Third-party kompatibel (Framer): SameSite=None; Secure; Partitioned
  pushSetCookie(
    res,
    `${COOKIE_NONCE}=${encodeURIComponent(nonce)}; Path=/; Max-Age=${maxAgeSec}; HttpOnly; SameSite=None; Secure; Partitioned`
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
  if (!out.domain || !out.address || !out.uri || !out.version || !out.chainId || !out.nonce || !out.issuedAt) {
    return null;
  }
  return out;
}

async function handler(req, res) {
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  }

  // 1) Origin-Gate (nach Preflight)
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

  // 3) SIWE parsen + Grundchecks
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

  // 4) Nonce-Handling (TOLERANT)
  // Nach verify(403) ist tc_nonce gelöscht. Für den zweiten verify-Call
  // setzen wir ihn hier **aus der SIWE-Message** neu, falls er fehlt.
  const cookieNonce = getCookie(req, COOKIE_NONCE);
  if (!cookieNonce) {
    setNonceCookie(res, siwe.nonce, 10 * 60);
  } else if (cookieNonce !== siwe.nonce) {
    // wenn vorhanden aber anders → vorsichtshalber überschreiben
    setNonceCookie(res, siwe.nonce, 10 * 60);
  }

  // 5) Signatur prüfen (wie in verify.js)
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

  // 6) Supabase: Wallet registrieren (upsert)
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
  const { error: upErr } = await sb
    .from("wallets")
    .upsert({ address: addressLower }, { onConflict: "address" });
  if (upErr) {
    console.error("[register] upsert wallets failed:", upErr);
    return res.status(500).json({ ok: false, code: "DB_UPSERT_ERROR" });
  }

  // optional: creator_name setzen, wenn user_id verknüpft ist
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
      console.warn("[register] profile update skipped:", e?.message || e);
    }
  }

  res.setHeader("Cache-Control", "no-store");
  // WICHTIG: Nonce NICHT löschen – der nächste /verify benötigt ihn.
  return res.status(200).json({ ok: true, registered: true });
}

export default withCors(handler);
// sicherstellen: Node runtime
export const config = { runtime: "nodejs" };
