import crypto from "crypto";
const SECRET = process.env.TC_SESSION_SECRET || "dev-insecure-change-me";
export function hmac(data: string) {
  return crypto.createHmac("sha256", SECRET).update(data).digest("base64url");
}
export function createSessionToken(address: string) {
  const ts = Math.floor(Date.now() / 1000);
  const payload = `${address}|${ts}`;
  const mac = hmac(payload);
  return Buffer.from(`${payload}|${mac}`).toString("base64url");
}
