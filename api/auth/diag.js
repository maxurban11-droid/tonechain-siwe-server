// api/auth/diag.js
export default async function handler(_req, res) {
  const url = (process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "").replace(/\/+$/, "");
  const host = url ? new URL(url).host : null;
  const hasRole = !!(process.env.SUPABASE_SERVICE_ROLE || process.env.SUPABASE_SERVICE_ROLE_KEY);
  res.status(200).json({
    ok: true,
    projectHost: host,          // <- muss sxqwohevhodeaiqcpygj.supabase.co sein
    hasServiceRole: hasRole,
    envFrom: process.env.SUPABASE_URL ? "SUPABASE_URL" : (process.env.NEXT_PUBLIC_SUPABASE_URL ? "NEXT_PUBLIC_SUPABASE_URL" : "none"),
  });
}
