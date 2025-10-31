// api/health.js — minimal & CORS-safe (ohne Credentials)
module.exports = (req, res) => {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*'); // ok, weil ohne Credentials
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    return res.status(204).end();
  }
  res.setHeader('Access-Control-Allow-Origin', '*'); // für einfachen GET ok
  res.status(200).json({ ok: true, health: 'up' });
};
