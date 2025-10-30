// helpers/env.ts
const csv = (v: string | undefined) => (v ? v.split(",").map(s => s.trim()).filter(Boolean) : []);

export const NODE_ENV = process.env.NODE_ENV ?? "development";
export const IS_PROD = NODE_ENV === "production";

// Comma-separated list, e.g. "https://*.framer.app,https://*.framer.website,https://framer.com,http://localhost:3000"
export const ORIGIN_WHITELIST = csv(process.env.ORIGIN_WHITELIST);
