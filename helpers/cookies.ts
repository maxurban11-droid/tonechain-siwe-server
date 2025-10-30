// helpers/cookies.ts
import type { VercelResponse } from "@vercel/node";
import { IS_PROD } from "./env";

export type CookieOptions = {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "lax" | "strict" | "none";
  path?: string;
  maxAge?: number; // seconds
};

const serialize = (name: string, value: string, opt: CookieOptions = {}) => {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (opt.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(opt.maxAge))}`);
  parts.push(`Path=${opt.path ?? "/"}`);
  if (opt.httpOnly) parts.push("HttpOnly");
  const sameSite = opt.sameSite ?? "lax";
  parts.push(`SameSite=${sameSite[0].toUpperCase()}${sameSite.slice(1)}`);
  const secure = opt.secure ?? IS_PROD;
  if (secure) parts.push("Secure");
  return parts.join("; ");
};

export function setCookie(res: VercelResponse, name: string, value: string, opt?: CookieOptions) {
  const existing = res.getHeader("Set-Cookie");
  const next = serialize(name, value, opt);
  if (!existing) {
    res.setHeader("Set-Cookie", next);
  } else if (Array.isArray(existing)) {
    res.setHeader("Set-Cookie", [...existing, next]);
  } else {
    res.setHeader("Set-Cookie", [String(existing), next]);
  }
}

export function clearCookie(res: VercelResponse, name: string, opt?: CookieOptions) {
  setCookie(res, name, "", { ...(opt ?? {}), maxAge: 0 });
}
