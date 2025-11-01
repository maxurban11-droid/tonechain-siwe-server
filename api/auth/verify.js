// /api/auth/verify.ts  — behutsam gehärtet
import type { VercelRequest, VercelResponse } from "@vercel/node";
// api/auth/verify.js — behutsam gehärtet
import { withCors } from "../../helpers/cors.js";
import { clearCookie, setCookie } from "../../helpers/cookies.js";
import { verifyMessage } from "ethers";

// Wir wrappen alles mit withCors → beantwortet OPTIONS korrekt mit CORS-Headers
export default withCors(async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });
  }

  try {
    const { message, signature } = req.body || {};
    if (!message || !signature) {
      return res
        .status(400)
        .json({ ok: false, error: "Missing message or signature" });
    }

    // ✅ Aktuell noch Platzhalter, später kommt hier die echte SIWE-Prüfung rein
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res
      .status(400)
      .json({ ok: false, error: e?.message || "Verify failed" });
  }
});


// ------- an deine Umgebung anpassen (klein halten, leicht revertierbar)
const ALLOWED_DOMAINS = new Set<string>([
  "tonechain.app",
  // Framer-Preview / Live:
  "concave-device-193297.framer.app",
]);

const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];

const ALLOWED_CHAINS = new Set<number>([1, 11155111]); // mainnet + sepolia
const MAX_AGE_MIN = 10;    // EIP-4361 IssuedAt darf nicht älter als 10min sein
const MAX_SKEW_MS = 5 * 60 * 1000; // ±5min Clock-Skew Toleranz

// Session/Nonce Cookie Namen (wie in deinem Projekt)
const COOKIE_NONCE = "tc_nonce";
const COOKIE_SESSION = "tc_session";

// kleine Helper
function safeJson<T = any>(s: string | null): T | null {
  try { return s ? JSON.parse(s) as T : null; } catch { return null; }
}
function now() { return Date.now(); }

// sehr leichte „DB“ für Signature-Replay (In-Memory, per Lambda kalt reset)
const seenSignatures = new Set<string>();

// EIP-4361 Parsen (wir lesen nur das, was wir wirklich brauchen)
type ParsedSiwe = {
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
};
function parseSiweMessage(msg: string): ParsedSiwe | null {
  try {
    // sehr einfache Zeilen-Extraktion – robust genug für unsere Message-Form
    const lines = msg.split("\n").map(l => l.trim());
    // Zeile 0: "<domain> wants you to sign in with your Ethereum account:"
    const domain = lines[0]?.split(" ")[0] || "";
    const address = lines[1] || "";
    const statement = lines[3] || "";
    // danach Key: Value Zeilen
    const fields = new Map<string,string>();
    for (let i=4;i<lines.length;i++){
      const [k, ...rest] = lines[i].split(":");
      if (!k || rest.length === 0) continue;
      fields.set(k.trim().toLowerCase(), rest.join(":").trim());
    }
    const uri = fields.get("uri") || "";
    const version = fields.get("version") || "1";
    const chainId = Number(fields.get("chain id") || "1");
    const nonce = fields.get("nonce") || "";
    const issuedAt = fields.get("issued at") || "";

    if (!domain || !address || !uri || !nonce || !issuedAt) return null;
    return { domain, address, statement, uri, version, chainId, nonce, issuedAt };
  } catch {
    return null;
  }
}

async function handler(req: VercelRequest, res: VercelResponse) {
  // Preflight handled by withCors
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  // Payload lesen
  const { message, signature } = safeJson<{message:string; signature:string}>(req.body as any) ?? {};
  if (!message || !signature) {
    return res.status(400).json({ ok: false, error: "Missing message or signature" });
  }

  // tc_nonce aus Cookie
  const nonceCookie = req.cookies?.[COOKIE_NONCE] || null;
  if (!nonceCookie) {
    return res.status(401).json({ ok: false, error: "Nonce missing (cookie)" });
  }

  // Message parsen
  const parsed = parseSiweMessage(message);
  if (!parsed) {
    return res.status(400).json({ ok: false, error: "Invalid SIWE message format" });
  }

  // 1) Domain / URI / Chain prüfen (behutsam, mit Whitelist)
  if (!ALLOWED_DOMAINS.has(parsed.domain)) {
    return res.status(400).json({ ok: false, error: "Domain not allowed" });
  }
  if (!ALLOWED_URI_PREFIXES.some(p => parsed.uri.startsWith(p))) {
    return res.status(400).json({ ok: false, error: "URI not allowed" });
  }
  if (!ALLOWED_CHAINS.has(parsed.chainId)) {
    return res.status(400).json({ ok: false, error: "Chain not allowed" });
  }

  // 2) Nonce aus Message == Cookie?
  if (parsed.nonce !== nonceCookie) {
    return res.status(401).json({ ok: false, error: "Nonce mismatch" });
  }

  // 3) IssuedAt Frische prüfen (<= MAX_AGE_MIN, ± Skew)
  const t = Date.parse(parsed.issuedAt);
  if (Number.isNaN(t)) {
    return res.status(400).json({ ok: false, error: "issuedAt invalid" });
  }
  const age = now() - t;
  if (age < -MAX_SKEW_MS || age > (MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS)) {
    return res.status(400).json({ ok: false, error: "Message too old" });
  }

  // 4) Signature Replay-Schutz (in-memory)
  if (seenSignatures.has(signature)) {
    return res.status(409).json({ ok: false, error: "Replay detected" });
  }

  // 5) Signatur verifizieren
  let recovered: string;
  try {
    recovered = await verifyMessage(message, signature);
  } catch (e: any) {
    return res.status(400).json({ ok: false, error: "Invalid signature", detail: e?.message });
  }
  const same = recovered?.toLowerCase() === parsed.address?.toLowerCase();
  if (!same) {
    return res.status(401).json({ ok: false, error: "Address mismatch" });
  }

  // 6) Erfolg → Nonce verwerfen, Session setzen
  seenSignatures.add(signature); // billig, reicht erstmal
  clearCookie(res, COOKIE_NONCE);

  // Session: einfache, signaturlose Variante (du hast das bereits im Einsatz)
  // Optional: hier stattdessen sessionId generieren + in DB/KV persistieren
  const sessionPayload = JSON.stringify({ a: recovered, iat: Date.now() });
  setCookie(res, COOKIE_SESSION, sessionPayload, {
    httpOnly: true,
    sameSite: "None",
    secure: true,
    path: "/",
    maxAge: 60 * 60 * 24 * 7, // 7 Tage
  });

  return res.status(200).json({ ok: true, address: recovered });
}

export default withCors(handler);
