// api/auth/register.js
// SIWE "register/link" – robustes CORS, Node runtime (ethers), Nonce wird NICHT gelöscht.

import { withCors } from "../../helpers/cors.js";

/* ---------- Policy ---------- */
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

/* ---------- Helpers ---------- */
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const hit = raw.split(/;\s*/).find((s) => s.startsWith(name + "="));
  return hit ? decodeURIComponent(hit.split("=").slice(1).join("=")) : null;
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
function readBearer(req) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

/* ---------- Handler ---------- */
async function handler(req, res) {
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });

  // Intent + Bearer
  const intent = String(req.headers["x-tc-intent"] || req.headers["X-TC-Intent"] || "").toLowerCase(); // "signup" | "link"
  const bearer = readBearer(req);

  // Body tolerant parsen
  let body = req.body;
  if (!body || typeof body !== "object") {
    try { body = JSON.parse(req.body || "{}"); } catch { body = {}; }
  }
  const message = body?.message;
  const signature = body?.signature;
  const creatorName = (body?.creatorName ?? "").trim() || null;

  if (!message || !signature) {
    return res.status(400).json({ ok: false, code: "INVALID_PAYLOAD", message: "Missing message or signature" });
  }

  // Server-Nonce
  const cookieNonce = getCookie(req, COOKIE_NONCE);
  if (!cookieNonce) return res.status(400).json({ ok: false, code: "MISSING_SERVER_NONCE" });

  // SIWE-Checks
  const siwe = parseSiweMessage(message);
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
  if (siwe.nonce !== cookieNonce) return res.status(401).json({ ok: false, code: "NONCE_MISMATCH" });

  // Signatur prüfen (Node runtime erforderlich)
  const ethersMod = await import("ethers");
  const verify =
    ethersMod.verifyMessage ||
    (ethersMod.default && ethersMod.default.verifyMessage) ||
    (ethersMod.utils && ethersMod.utils.verifyMessage);
  if (typeof verify !== "function") return res.status(500).json({ ok: false, code: "VERIFY_UNAVAILABLE" });

  const recovered = await verify(message, signature);
  if (!addrEq(recovered, siwe.address)) return res.status(401).json({ ok: false, code: "ADDRESS_MISMATCH" });

  // Supabase Admin
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
  }
  const { createClient } = await import("@supabase/supabase-js");
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

  const addressLower = String(siwe.address || "").toLowerCase();

  /* ---- 1) Wallet-Row sicherstellen (unique by address) ---- */
  {
    const { error: upErr } = await sb
      .from("wallets")
      .upsert({ address: addressLower }, { onConflict: "address", ignoreDuplicates: false });
    if (upErr) {
      console.error("[register] upsert wallets failed:", upErr);
      return res.status(500).json({ ok: false, code: "DB_UPSERT_ERROR" });
    }
  }

  // Aktuellen Wallet-Status lesen
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

  if (intent === "link" && bearer) {
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
    if (!linkProfileId) {
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
    }

    // Wallet gehört schon jemand anderem?
    if (walletRow?.user_id && walletRow.user_id !== linkProfileId) {
      return res.status(409).json({
        ok: false,
        code: "WALLET_ALREADY_LINKED",
        message: "This wallet is already linked to another profile.",
      });
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
        // lost race – reread
        const { data: again } = await sb
          .from("wallets")
          .select("user_id")
          .eq("address", addressLower)
          .maybeSingle();
        if (!again?.user_id) {
          return res.status(409).json({ ok: false, code: "LINK_RACE_CONFLICT" });
        }
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
    if (profileId) {
      // Bereits registriert → idempotent erfolgreich
      res.setHeader("Cache-Control", "no-store");
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

    // Profil erzeugen (vorerst ohne user_id, falls ihr E-Mail separat nutzt)
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
      // Lost race: jemand anderes hat parallel gelinkt → neu erzeugtes Profil aufräumen
      await sb.from("profiles").delete().eq("id", prof.id).catch(() => {});
      const { data: again } = await sb
        .from("wallets")
        .select("user_id")
        .eq("address", addressLower)
        .maybeSingle();
      if (!again?.user_id) {
        return res.status(409).json({ ok: false, code: "SIGNUP_RACE_CONFLICT" });
      }
      profileId = again.user_id;
    } else {
      profileId = upd[0]?.user_id ?? prof.id;
    }
  }

  // Optional: Creator-Name nachtragen, falls vorhanden
  if (creatorName && profileId) {
    await sb.from("profiles").update({ creator_name: creatorName }).eq("id", profileId).catch(() => {});
  }

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({
    ok: true,
    registered: true,
    address: addressLower,
    userId: profileId ?? linkProfileId ?? null,
    keepNonce: true,    // wichtig: Verify darf danach sofort erneut erfolgen
    linked: Boolean(linkProfileId),
  });
}

export default withCors(handler);
// Node-Runtime erzwingen (ethers)
export const config = { runtime: "nodejs" };
