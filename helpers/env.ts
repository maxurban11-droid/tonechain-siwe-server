export const isProd = process.env.NODE_ENV === "production";
export const ORIGIN_WHITELIST = (process.env.ORIGIN_WHITELIST || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
export const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 60 * 60 * 24 * 7);
export const NONCE_TTL_SECONDS = Number(process.env.NONCE_TTL_SECONDS || 10 * 60);
