// helpers/cors.ts
const ALLOW_METHODS = "GET,POST,OPTIONS";
const ALLOW_HEADERS = "content-type";
const CREDENTIALS = "true";

function allowOriginFor(req: Request) {
  const o = req.headers.get("Origin");
  // 👉 trage deine erlaubten Origins hier ein
  const allowed = [
    "https://framer.com",
    "https://*.framer.app",
    "https://*.framer.website",
    "https://tonechain.framer.website",
  ];
  if (!o) return "*"; // für Healthchecks o.Ä. – optional
  try {
    const ok = allowed.some(p =>
      p.startsWith("https://*.") ? o.endsWith(p.slice(10)) : o === p
    );
    return ok ? o : o; // im Zweifel Echo-Back, aber in Prod lieber blocken
  } catch {
    return o ?? "*";
  }
}

export function cors(req: Request, res: Response) {
  const origin = allowOriginFor(req);
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", origin);
  h.set("Access-Control-Allow-Credentials", CREDENTIALS);
  h.set("Access-Control-Allow-Methods", ALLOW_METHODS);
  h.set("Access-Control-Allow-Headers", ALLOW_HEADERS);
  h.set("Vary", "Origin");
  return new Response(res.body, { status: res.status, headers: h });
}

export function preflight(req: Request) {
  // 204 leerer Body
  return cors(req, new Response(null, { status: 204 }));
}
