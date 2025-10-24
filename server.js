// Railway uses env vars directly - dotenv not needed
// require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const Database = require('better-sqlite3');

const {
  PORT = 8787,
  FS_WEBHOOK_SECRET,
  GOOGLE_CLIENT_ID,
  CORS_ORIGIN = 'https://clickto.es',
} = process.env;
if (!FS_WEBHOOK_SECRET) throw new Error('FS_WEBHOOK_SECRET is required');
if (!GOOGLE_CLIENT_ID) throw new Error('GOOGLE_CLIENT_ID is required');

const db = new Database('premium.db');
db.pragma('journal_mode = WAL');
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    premium INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
  )
`).run();

const upsertPremium = db.prepare(`
  INSERT INTO users (email, premium, updated_at)
  VALUES (@email, @premium, @updated_at)
  ON CONFLICT(email) DO UPDATE SET
    premium=excluded.premium,
    updated_at=excluded.updated_at
`);

const getPremiumByEmail = db.prepare(`SELECT premium FROM users WHERE email = ?`);

const app = express();

app.use(cors({
  origin: CORS_ORIGIN.split(',').map(s => s.trim()),
  credentials: false,
}));

app.get('/health', (_req, res) => res.json({ ok: true }));

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
async function verifyGoogleIdToken(idToken) {
  const ticket = await googleClient.verifyIdToken({
    idToken,
    audience: GOOGLE_CLIENT_ID,
  });
  const payload = ticket.getPayload();
  return payload;
}
async function requireGoogleAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const [, token] = auth.split(' ');
    if (!token) return res.status(401).json({ error: 'Missing Bearer token' });
    const payload = await verifyGoogleIdToken(token);
    if (!payload?.email) return res.status(401).json({ error: 'Invalid token' });
    req.userEmail = payload.email.toLowerCase();
    next();
  } catch (e) {
    console.error('Auth error:', e.message);
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

app.get('/api/premium/me', requireGoogleAuth, (req, res) => {
  const row = getPremiumByEmail.get(req.userEmail);
  res.json({ email: req.userEmail, premium: !!(row && row.premium) });
});

app.post('/api/premium/activate', express.json(), (req, res) => {
  const { email, premium } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email is required' });
  upsertPremium.run({
    email: email.toLowerCase(),
    premium: premium ? 1 : 0,
    updated_at: new Date().toISOString(),
  });
  res.json({ ok: true });
});

app.post('/webhooks/fastspring',
  express.raw({ type: '*/*' }),
  (req, res) => {
    try {
      const signature = req.header('X-FS-Signature') || '';
      const raw = req.body;
      const expected = crypto
        .createHmac('sha256', FS_WEBHOOK_SECRET)
        .update(raw)
        .digest('base64');

      const ok = crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
      if (!ok) {
        console.warn('❌ FastSpring signature mismatch');
        return res.status(401).end();
      }

      const payload = JSON.parse(raw.toString('utf8'));
      const events = Array.isArray(payload?.events) ? payload.events : [];

      events.forEach(ev => {
        const type = ev?.type || '';
        const email =
          ev?.data?.customer?.email ||
          ev?.data?.order?.customer?.email ||
          ev?.data?.subscription?.customer?.email ||
          null;

        if (!email) return;

        const activateTypes = new Set([
          'order.completed',
          'subscription.activated',
          'subscription.charge.completed',
          'subscription.payment.completed'
        ]);

        const deactivateTypes = new Set([
          'subscription.deactivated',
          'subscription.canceled',
          'subscription.payment.failed'
        ]);

        if (activateTypes.has(type)) {
          upsertPremium.run({
            email: email.toLowerCase(),
            premium: 1,
            updated_at: new Date().toISOString()
          });
          console.log(`⭐ Premium activated for ${email} via ${type}`);
        } else if (deactivateTypes.has(type)) {
          upsertPremium.run({
            email: email.toLowerCase(),
            premium: 0,
            updated_at: new Date().toISOString()
          });
          console.log(`🛑 Premium deactivated for ${email} via ${type}`);
        } else {
          console.log('ℹ️ FS event:', type, 'email:', email);
        }
      });

      res.status(200).end();
    } catch (e) {
      console.error('Webhook handler error:', e);
      return res.status(400).end();
    }
  }
);

app.listen(PORT, () => {
  console.log(`✅ Server listening on :${PORT}`);
});
