// helpers/cors.ts — CORS-Helper, kompatibel mit Cookies (credentials: "include")

const DEFAULT_WHITELIST: RegExp[] = [
  /^https?:\/\/localhost(:\d+)?$/i,
  /^http:\/\/127\.0\.0\.1(:\d+)?$/i,
  /^https:\/\/framer\.com$/i,
  /^https:\/\/.*\.framer\.app$/i,
  /^https:\/\/.*\.framer\.website$/i,
  /^https:\/\/.*\.vercel\.app$/i,
  /^https:\/\/(www\.)?tonechain\.app$/i,
];

// Optional: zusätzliche Origins per ENV, komma-getrennt, Wildcards erlaubt (z.B. "*.dein-domain.tld")
function envWhitelist(): RegExp[] {
  const raw = process.env.ALLOWED_ORIGINS || "";
  return raw
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
    .map((pat) => {
      // "*.foo.bar" -> /^https:\/\/.*\.foo\.bar$/i
      const esc = pat
        .replace(/\./g, "\\.")
        .replace(/\*/g, ".*");
      return new RegExp(`^https?:\/\/${esc}$`, "i");
    });
}

function pickAllowedOrigin(origin: string | null): string | null {
  if (!origin) return null;
  const all = [...DEFAULT_WHITELIST, ...envWhitelist()];
  return all.some(rx => rx.test(origin)) ? origin : null;
}

type CorsOpts = {
  methods?: string[];
  headers?: string[];
  maxAgeSec?: number;
};

export function cors(req: Request, res: Response, opts: CorsOpts = {}): Response {
  const origin = req.headers.get("origin");
  const allowed = pickAllowedOrigin(origin);

  const h = new Headers(res.headers);

  if (allowed) {
    h.set("Access-Control-Allow-Origin", allowed);
    h.append("Vary", "Origin"); // wichtig für richtige CDN-Caching-Variante
    h.set("Access-Control-Allow-Credentials", "true");
  } else {
    // Keine Wildcard verwenden, wenn Credentials beteiligt sind!
    // Wenn Origin nicht whitelisted ist: lieber gar keinen ACAO-Header setzen.
  }

  h.set("Access-Control-Allow-Methods", (opts.methods ?? ["GET", "POST", "OPTIONS"]).join(","));
  h.set(
    "Access-Control-Allow-Headers",
    (opts.headers ?? ["Content-Type", "Authorization", "X-Requested-With"]).join(",")
  );
  h.set("Access-Control-Max-Age", String(opts.maxAgeSec ?? 600));

  return new Response(res.body, { status: res.status, headers: h });
}

export function preflight(req: Request, opts?: CorsOpts): Response {
  // 204 ohne Body, aber mit CORS-Headern
  return cors(req, new Response(null, { status: 204 }), opts);
}
