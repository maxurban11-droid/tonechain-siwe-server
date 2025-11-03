// /api/auth/verify.js — stabile SIWE-Verify-Route + feinere Fehlerdiagnose (Node runtime)
import crypto from "node:crypto";

/* ==== Config (unverändert) ==== */
const ALLOWED_DOMAINS = new Set(["tonechain.app","concave-device-193297.framer.app"]);
const ALLOWED_URI_PREFIXES = ["https://tonechain.app","https://concave-device-193297.framer.app"];
const ALLOWED_CHAINS = new Set([1, 11155111]);
const MAX_AGE_MIN = 10, MAX_SKEW_MS = 5*60*1000;
const COOKIE_NONCE = "tc_nonce", COOKIE_SESSION = "tc_session", SESSION_TTL_SEC = 60*60*24;
const SESSION_SECRET = process.env.SESSION_SECRET || null;

/* ==== Helpers ==== */
const sign = v => SESSION_SECRET ? crypto.createHmac("sha256", SESSION_SECRET).update(v).digest("hex") : null;
function setCookie(res, name, value, opts={}) {
  const parts = [`${name}=${value}`,"Path=/","HttpOnly","SameSite=None","Secure"];
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev)?prev:prev?[String(prev)]:[]), parts.join("; ")]);
}
function clearCookie(res, name) {
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev)?prev:prev?[String(prev)]:[]), del]);
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const m = raw.split(/;\s*/).find(s => s.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : null;
}
function withinAge(iso){
  const t = Date.parse(iso); if(!Number.isFinite(t)) return false;
  return Math.abs(Date.now()-t) <= MAX_AGE_MIN*60*1000 + MAX_SKEW_MS;
}
const addrEq = (a,b)=> String(a||"").toLowerCase() === String(b||"").toLowerCase();
function parseSiweMessage(msg){
  const lines = String(msg||"").split("\n"); if(lines.length<8) return null;
  const domain = (lines[0]||"").split(" ")[0]||"", address = (lines[1]||"").trim();
  let i=2; while(i<lines.length && !/^[A-Za-z ]+:\s/.test(lines[i])) i++;
  const fields={}; for(;i<lines.length;i++){ const row=lines[i]; const k=row.slice(0,row.indexOf(":")).trim().toLowerCase(); const v=row.slice(row.indexOf(":")+1).trim(); if(k) fields[k]=v; }
  const out={ domain, address, uri:fields["uri"], version:fields["version"], chainId:Number(fields["chain id"]), nonce:fields["nonce"], issuedAt:fields["issued at"] };
  if(!out.domain||!out.address||!out.uri||!out.version||!out.chainId||!out.nonce||!out.issuedAt) return null;
  return out;
}

/* ==== Handler ==== */
export default async function handler(req,res){
  // CORS immer zuerst
  const origin = req.headers.origin || "";
  res.setHeader("Vary","Origin");
  res.setHeader("Access-Control-Allow-Origin", origin || "*");
  res.setHeader("Access-Control-Allow-Credentials","true");
  res.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers","Content-Type, Authorization");
  if(req.method==="OPTIONS") return res.status(204).end();
  if(req.method!=="POST") return res.status(405).json({ ok:false, code:"METHOD_NOT_ALLOWED" });

  try {
    // 1) Origin-Check
    let allowed=false; try{ if(origin){ allowed = ALLOWED_DOMAINS.has(new URL(origin).hostname); } }catch{}
    if(!allowed){ res.setHeader("X-TC-Debug","stage=origin"); return res.status(403).json({ ok:false, code:"ORIGIN_NOT_ALLOWED" }); }

    // 2) Payload + Nonce
    const { message, signature } = req.body || {};
    if(!message||!signature){ res.setHeader("X-TC-Debug","stage=payload"); return res.status(400).json({ ok:false, code:"INVALID_PAYLOAD" }); }
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    if(!cookieNonce){ res.setHeader("X-TC-Debug","stage=nonce"); return res.status(400).json({ ok:false, code:"MISSING_SERVER_NONCE" }); }

    // 3) SIWE-Parse + Checks
    const siwe = parseSiweMessage(message);
    if(!siwe){ res.setHeader("X-TC-Debug","stage=siwe-parse"); return res.status(400).json({ ok:false, code:"INVALID_SIWE_FORMAT" }); }
    if(!ALLOWED_DOMAINS.has(siwe.domain)){ res.setHeader("X-TC-Debug","stage=siwe-domain"); return res.status(400).json({ ok:false, code:"DOMAIN_NOT_ALLOWED" }); }
    try{
      const u=new URL(siwe.uri);
      if(!ALLOWED_URI_PREFIXES.some(p=>u.href.startsWith(p))){ res.setHeader("X-TC-Debug","stage=siwe-uri"); return res.status(400).json({ ok:false, code:"URI_NOT_ALLOWED" }); }
    }catch{ res.setHeader("X-TC-Debug","stage=siwe-uri-parse"); return res.status(400).json({ ok:false, code:"URI_NOT_ALLOWED" }); }
    if(!ALLOWED_CHAINS.has(Number(siwe.chainId))){ res.setHeader("X-TC-Debug","stage=siwe-chain"); return res.status(400).json({ ok:false, code:"CHAIN_NOT_ALLOWED" }); }
    if(!withinAge(siwe.issuedAt)){ res.setHeader("X-TC-Debug","stage=siwe-age"); return res.status(400).json({ ok:false, code:"MESSAGE_TOO_OLD" }); }
    if(siwe.nonce !== cookieNonce){ res.setHeader("X-TC-Debug","stage=siwe-nonce"); return res.status(401).json({ ok:false, code:"NONCE_MISMATCH" }); }

    // 4) Signatur prüfen
    let recovered;
    try{
      const mod = await import("ethers");
      const verify = mod.verifyMessage || (mod.default&&mod.default.verifyMessage) || (mod.utils&&mod.utils.verifyMessage);
      if(typeof verify!=="function"){ res.setHeader("X-TC-Debug","stage=ethers-missing"); return res.status(500).json({ ok:false, code:"VERIFY_UNAVAILABLE" }); }
      recovered = await verify(message, signature);
    }catch(e){
      console.error("[SIWE] ethers verify error:", e);
      res.setHeader("X-TC-Debug","stage=ethers-throw");
      return res.status(400).json({ ok:false, code:"SIGNATURE_VERIFY_FAILED" });
    }
    if(!addrEq(recovered, siwe.address)){ res.setHeader("X-TC-Debug","stage=addr-mismatch"); return res.status(401).json({ ok:false, code:"ADDRESS_MISMATCH" }); }

    // 5) Supabase Admin
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if(!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY){
      res.setHeader("X-TC-Debug","stage=sb-config-missing");
      return res.status(500).json({ ok:false, code:"SERVER_CONFIG_MISSING" });
    }

    let sbAdmin;
    try{
      const { createClient } = await import("@supabase/supabase-js");
      sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth:{ persistSession:false }});
    }catch(e){
      console.error("[SIWE] supabase import/create error:", e);
      res.setHeader("X-TC-Debug","stage=sb-init");
      return res.status(500).json({ ok:false, code:"DB_INIT_ERROR" });
    }

    const addressLower = String(siwe.address||"").toLowerCase();

    // 6) RPC wallet_registered
    try{
      const { data: isRegistered, error: regErr } = await sbAdmin.rpc("wallet_registered", { p_address: addressLower });
      if(regErr){ console.error("[SIWE] wallet_registered rpc error:", regErr); res.setHeader("X-TC-Debug","stage=rpc-fail"); return res.status(500).json({ ok:false, code:"DB_ERROR" }); }
      if(!isRegistered){
        clearCookie(res, COOKIE_NONCE);
        res.setHeader("X-TC-Debug","stage=rpc-not-registered");
        return res.status(403).json({ ok:false, code:"WALLET_NOT_REGISTERED", message:"No account found for this wallet. Please sign up first." });
      }
    }catch(e){
      console.error("[SIWE] rpc call throw:", e);
      res.setHeader("X-TC-Debug","stage=rpc-throw");
      return res.status(500).json({ ok:false, code:"DB_ERROR" });
    }

    // 7) user_id Lookup (optional)
    let userId = null;
    try{
      const { data: row } = await sbAdmin.from("wallets").select("user_id").eq("address", addressLower).maybeSingle();
      userId = row?.user_id ?? null;
    }catch(e){
      console.warn("[SIWE] wallets lookup warn:", e);
      res.setHeader("X-TC-Debug","stage=wallets-lookup-warn");
    }

    // 8) Session
    try{
      const payload = { v:1, addr:addressLower, userId, ts:Date.now(), exp:Date.now()+SESSION_TTL_SEC*1000 };
      const raw = JSON.stringify(payload);
      const sig = sign(raw);
      const sessionValue = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");
      clearCookie(res, COOKIE_NONCE);
      setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });
    }catch(e){
      console.error("[SIWE] session set failed:", e);
      res.setHeader("X-TC-Debug","stage=session-set");
      return res.status(500).json({ ok:false, code:"SESSION_SET_FAILED" });
    }

    res.setHeader("X-TC-Debug","stage=ok");
    return res.status(200).json({ ok:true, address:addressLower, userId });
  } catch (e) {
    console.error("[SIWE verify] unexpected error:", e);
    res.setHeader("X-TC-Debug","stage=catch");
    return res.status(500).json({ ok:false, code:"INTERNAL_ERROR" });
  }
}

// Node runtime sicherstellen (kein Edge)
export const config = { runtime: "nodejs" };
