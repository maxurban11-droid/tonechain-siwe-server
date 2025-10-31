// helpers/cors.js
const ORIGIN_WHITELIST = [
   // deine veröffentlichte Framer-Site:
   "https://concave-device-193297.framer.app",
   // Framer Editor / Live Preview:
   "https://framer.com",
   "https://*.framer.app",
   "https://*.framer.website",
   // Lokal
   "http://localhost:3000",
 ];

function isAllowed(origin) {
  if (!origin) return null;
  const o = origin.replace(/\/+$/, "").toLowerCase();
  for (const entryRaw of ORIGIN_WHITELIST) {
    const entry = String(entryRaw).replace(/\/+$/, "").toLowerCase();
    if (!entry.includes("*")) {
      if (o === entry) return o;
      continue;
    }
    // nur Subdomain-Wildcard (*.domain.tld)
    const esc = entry
      .replace(/[-/\\^$+?.()|[\]{}]/g, "\\$&")
      .replace(/\\\*\\\./g, "(?:[a-z0-9-]+\\.)+");
    const re = new RegExp(`^${esc}$`, "i");
    if (re.test(o)) return o;
  }
  return null;
}

async function withCors(req, res) {
  const allowed = isAllowed(req.headers.origin || "");
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", allowed);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Authorization,Accept,X-Requested-With"
  );
  res.setHeader("Access-Control-Max-Age", "86400");
  return res;
}

function handleOptions(req, res) {
  withCors(req, res);
  return res.status(204).end();
}

module.exports = { withCors, handleOptions };
