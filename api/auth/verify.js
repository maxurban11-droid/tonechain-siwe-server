// api/auth/verify.js
import { randomUUID } from "crypto";

function allowCors(req, res) {
  const origin = req.headers.origin || "";
  const allow =
    /^https:\/\/([a-z0-9-]+\.)?framer\.app$/.test(origin) ||
    origin.includes("framer.com") ||
    origin.includes("localhost");

  if (allow) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
}

function getCookie(req, name) {
  const h = req.headers.cookie || "";
  const m = h.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : null;
}
function clearCookie(name) {
  return [
    `${name}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    "Max-Age=0",
  ].join("; ");
}
function setSessionCookie(value, maxAge = 60 * 60 * 24 * 14) {
  return [
    `tc_session=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    `Max-Age=${maxAge}`,
  ].join("; ");
}

// robustes import für ethers v5 oder v6
async function verifyWithEthers(message, signature) {
  try {
    // ethers v6
    const { verifyMessage } = await import("ethers");
    return verifyMessage(message, signature);
  } catch {
    // ethers v5
    const { utils } = await import("ethers/lib/utils.js");
    return utils.verifyMessage(message, signature);
  }
}

export default async function handler(req, res) {
  allowCors(req, res);

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")
    return res.status(405).json({ ok: false, error: "Method not allowed" });

  try {
    const { message, signature } = (await readJson(req)) || {};
    if (!message || !signature)
      return res.status(400).json({ ok: false, error: "Missing payload" });

    // 1) Nonce aus Message extrahieren (Zeile "Nonce: <value>")
    const nonceInMsg = (message.match(/^\s*Nonce:\s*([^\s]+)\s*$/mi) || [])[1];
    if (!nonceInMsg)
      return res.status(400).json({ ok: false, error: "Nonce missing in message" });

    // 2) Cookie vergleichen
    const nonceCookie = getCookie(req, "tc_nonce");
    if (!nonceCookie) {
      return res.status(401).json({ ok: false, error: "Nonce cookie missing" });
    }
    if (nonceCookie !== nonceInMsg) {
      return res.status(401).json({ ok: false, error: "Nonce mismatch" });
    }

    // 3) Signatur prüfen → Adresse recovern
    let recovered;
    try {
      recovered = await verifyWithEthers(message, signature);
    } catch (e) {
      return res
        .status(400)
        .json({ ok: false, error: "Invalid signature", detail: String(e?.message || e) });
    }

    // 4) Nonce invalidieren + Session setzen
    const sessionPayload = JSON.stringify({
      v: 1,
      addr: recovered,
      iat: Date.now(),
      sid: randomUUID(),
    });

    res.setHeader("Set-Cookie", [
      clearCookie("tc_nonce"),
      setSessionCookie(sessionPayload),
    ]);

    return res.status(200).json({ ok: true, address: recovered });
  } catch (e) {
    return res
      .status(500)
      .json({ ok: false, error: "Server error", detail: String(e?.message || e) });
  }
}

// Body lesen (ohne zusätzliche deps)
function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}
