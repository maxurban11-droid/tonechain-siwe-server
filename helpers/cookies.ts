import { NextResponse } from "next/server";
import { isProd } from "./env";

type CookieOpts = {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "lax" | "strict" | "none" | "Lax" | "Strict" | "None";
  path?: string;
  maxAge?: number;
};

export function setCookie(
  res: NextResponse,
  name: string,
  value: string,
  opts: CookieOpts = {}
) {
  res.cookies.set({
    name,
    value,
    httpOnly: opts.httpOnly ?? true,
    secure: opts.secure ?? isProd,
    sameSite: (opts.sameSite ?? "lax") as any,
    path: opts.path ?? "/",
    maxAge: opts.maxAge
  });
}

export function clearCookie(res: NextResponse, name: string, opts: CookieOpts = {}) {
  res.cookies.set({
    name,
    value: "",
    httpOnly: opts.httpOnly ?? true,
    secure: opts.secure ?? isProd,
    sameSite: (opts.sameSite ?? "lax") as any,
    path: opts.path ?? "/",
    maxAge: 0
  });
}
