// api/auth/verify.js
async function loadEthers() {
  try {
    // v6 style
    const m = await import("ethers");
    return m.default || m;
  } catch (e1) {
    try {
      // v5 fallback (CommonJS)
      const m = await import("ethers/lib/index.js");
      return m.default || m;
    } catch (e2) {
      return null;
    }
  }
}

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(/; */)) {
    const [k, ...rest] = part.split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

function parseSiwe(msg) {
  // Sehr schlanke Parser — reicht für unsere Checks.
  // Adresse = zweite Zeile
  const addrMatch = msg.match(/\n(0x[a-fA-F0-9]{40})\n/);
  const address = addrMatch ? addrMatch[1] : null;

  // Nonce-Zeile
  const nonceMatch = msg.match(/\nNonce:\s*([A-Za-z0-9-]+)\s*\n/);
  const nonce = nonceMatch ? nonceMatch[1] : null;

  return { address, nonce };
}

export default async function handler(req, res) {
  // --- CORS / Preflight ---
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }

  // --- CORS header für Antwort ---
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  let body;
  try {
    body = req.body || {};
  } catch {
    body = {};
  }
  const { message, signature } = body || {};
  if (!message || typeof message !== "string") {
    return res.status(400).json({ ok: false, error: "Missing message" });
  }
  if (!signature || typeof signature !== "string") {
    return res.status(400).json({ ok: false, error: "Missing signature" });
  }

  // Cookie-Nonce prüfen
  const cookieNonce = getCookie(req, "tc_nonce");
  const { address: msgAddress, nonce: msgNonce } = parseSiwe(message);

  if (!msgAddress || !msgNonce) {
    return res.status(400).json({ ok: false, error: "Invalid SIWE message format" });
  }
  if (!cookieNonce || cookieNonce !== msgNonce) {
    return res.status(401).json({ ok: false, error: "Nonce mismatch" });
  }

  // Signatur verifizieren (ethers v6/v5)
  const ethers = await loadEthers();
  if (!ethers) {
    return res
      .status(500)
      .json({ ok: false, error: "Server missing dependency 'ethers'. Please install it." });
  }

  let recovered;
  try {
    // v6: ethers.verifyMessage(msg, sig)
    if (typeof ethers.verifyMessage === "function") {
      recovered = ethers.verifyMessage(message, signature);
    } else if (ethers.utils?.verifyMessage) {
      // v5
      recovered = ethers.utils.verifyMessage(message, signature);
    } else {
      throw new Error("Unsupported ethers version");
    }
  } catch (e) {
    return res.status(400).json({ ok: false, error: "Invalid signature format" });
  }

  if (!recovered || recovered.toLowerCase() !== msgAddress.toLowerCase()) {
    return res.status(401).json({ ok: false, error: "Signature does not match address" });
  }

  // Session setzen und Nonce invalidieren
  const isProd =
    process.env.VERCEL_ENV === "production" || process.env.NODE_ENV === "production";
  const token = Buffer.from(
    JSON.stringify({ a: msgAddress, iat: Date.now() }),
    "utf8"
  ).toString("base64url");

  const sessionCookie = [
    `tc_session=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    // 7 Tage
    `Max-Age=${60 * 60 * 24 * 7}`,
    isProd ? "Secure" : null,
  ].filter(Boolean);

  const killNonce = [
    "tc_nonce=;",
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=0",
    isProd ? "Secure" : null,
  ].filter(Boolean);

  res.setHeader("Set-Cookie", [sessionCookie.join("; "), killNonce.join("; ")]);

  return res.status(200).json({ ok: true });
}
