// Railway/Render uses env vars directly - dotenv not needed
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const Database = require('better-sqlite3');

const {
  PORT = 8787,
  FS_WEBHOOK_SECRET,
  GOOGLE_CLIENT_ID,
  CORS_ORIGIN = '*', // Allow all origins for mobile app
} = process.env;

// Flexible: FS_WEBHOOK_SECRET optional for development
const requireWebhookSecret = !!FS_WEBHOOK_SECRET;
if (!GOOGLE_CLIENT_ID) throw new Error('GOOGLE_CLIENT_ID is required');

const db = new Database('premium.db');
db.pragma('journal_mode = WAL');

db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    premium INTEGER NOT NULL DEFAULT 0,
    order_id TEXT,
    activated_at TEXT,
    updated_at TEXT NOT NULL
  )
`).run();

const upsertPremium = db.prepare(`
  INSERT INTO users (email, premium, order_id, activated_at, updated_at)
  VALUES (@email, @premium, @order_id, @activated_at, @updated_at)
  ON CONFLICT(email) DO UPDATE SET
    premium=excluded.premium,
    order_id=excluded.order_id,
    activated_at=excluded.activated_at,
    updated_at=excluded.updated_at
`);

const getPremiumByEmail = db.prepare(`SELECT * FROM users WHERE email = ?`);
const getAllPremiumUsers = db.prepare(`SELECT email, premium, activated_at FROM users WHERE premium = 1`);

const app = express();

// CORS for mobile apps
app.use(cors({
  origin: CORS_ORIGIN === '*' ? '*' : CORS_ORIGIN.split(',').map(s => s.trim()),
  credentials: false,
}));

// Health check
app.get('/', (_req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'OrbitSpeed Premium Webhook',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (_req, res) => res.json({ ok: true }));

// ✅ ANDROID APP: Check premium status by email (no auth required)
app.get('/webhooks/fastspring/check', (req, res) => {
  const email = req.query.email;
  
  console.log(`\n🔍 Premium check for: ${email}`);
  
  if (!email) {
    return res.status(400).json({ error: 'Email parameter required' });
  }
  
  const row = getPremiumByEmail.get(email.toLowerCase());
  const isPremium = !!(row && row.premium);
  
  console.log(`Premium status: ${isPremium}`);
  
  res.json({ 
    premium: isPremium,
    email: email.toLowerCase(),
    data: row ? {
      activated_at: row.activated_at,
      order_id: row.order_id
    } : null
  });
});

// ✅ ANDROID APP: Manual premium activation (for testing)
app.post('/webhooks/fastspring/activate', express.json(), (req, res) => {
  const email = req.body.email || req.query.email;
  const premium = req.body.premium !== undefined ? req.body.premium : true;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  const now = new Date().toISOString();
  
  upsertPremium.run({
    email: email.toLowerCase(),
    premium: premium ? 1 : 0,
    order_id: 'MANUAL-' + Date.now(),
    activated_at: premium ? now : null,
    updated_at: now
  });
  
  console.log(`✅ Manual premium ${premium ? 'activated' : 'deactivated'} for: ${email}`);
  
  res.json({ 
    success: true, 
    message: `Premium ${premium ? 'activated' : 'deactivated'} for ${email}`,
    premium: premium
  });
});

// ✅ LIST ALL PREMIUM USERS (for debugging)
app.get('/webhooks/fastspring/users', (req, res) => {
  const users = getAllPremiumUsers.all();
  res.json({ 
    count: users.length,
    users: users 
  });
});

// Google Auth middleware (optional for /api/premium/me)
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

async function verifyGoogleIdToken(idToken) {
  if (!googleClient) throw new Error('Google client not configured');
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

// ✅ WEB APP: Check premium with Google Auth
app.get('/api/premium/me', requireGoogleAuth, (req, res) => {
  const row = getPremiumByEmail.get(req.userEmail);
  res.json({ 
    email: req.userEmail, 
    premium: !!(row && row.premium),
    data: row || null
  });
});

// ✅ FASTSPRING WEBHOOK HANDLER
app.post('/webhooks/fastspring',
  express.raw({ type: '*/*' }),
  (req, res) => {
    console.log('\n🔔 FastSpring webhook received');
    
    try {
      const signature = req.header('X-FS-Signature') || '';
      const raw = req.body;

      // Verify signature if FS_WEBHOOK_SECRET is set
      if (requireWebhookSecret) {
        const expected = crypto
          .createHmac('sha256', FS_WEBHOOK_SECRET)
          .update(raw)
          .digest('base64');

        const ok = crypto.timingSafeEqual(
          Buffer.from(signature), 
          Buffer.from(expected)
        );
        
        if (!ok) {
          console.warn('❌ FastSpring signature mismatch');
          return res.status(401).json({ error: 'Invalid signature' });
        }
      } else {
        console.warn('⚠️ Webhook signature verification disabled (no FS_WEBHOOK_SECRET)');
      }

      const payload = JSON.parse(raw.toString('utf8'));
      const events = Array.isArray(payload?.events) ? payload.events : [];

      console.log(`📦 Processing ${events.length} events`);

      events.forEach(ev => {
        const type = ev?.type || '';
        const email =
          ev?.data?.customer?.email ||
          ev?.data?.order?.customer?.email ||
          ev?.data?.subscription?.customer?.email ||
          null;

        if (!email) {
          console.log(`⚠️ No email found in event: ${type}`);
          return;
        }

        const orderId = ev?.data?.id || ev?.data?.order?.id || null;

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

        const now = new Date().toISOString();

        if (activateTypes.has(type)) {
          upsertPremium.run({
            email: email.toLowerCase(),
            premium: 1,
            order_id: orderId,
            activated_at: now,
            updated_at: now
          });
          console.log(`✅ Premium activated for ${email} via ${type} (Order: ${orderId})`);
        } else if (deactivateTypes.has(type)) {
          upsertPremium.run({
            email: email.toLowerCase(),
            premium: 0,
            order_id: orderId,
            activated_at: null,
            updated_at: now
          });
          console.log(`🛑 Premium deactivated for ${email} via ${type}`);
        } else {
          console.log(`ℹ️ Unhandled event: ${type} for ${email}`);
        }
      });

      res.status(200).json({ success: true, processed: events.length });
      
    } catch (e) {
      console.error('❌ Webhook handler error:', e);
      return res.status(500).json({ error: e.message });
    }
  }
);

app.listen(PORT, () => {
  console.log(`\n✅ Server running on port ${PORT}`);
  console.log(`📡 Webhook URL: https://backend-clean-u89k.onrender.com/webhooks/fastspring`);
  console.log(`🔍 Check endpoint: https://backend-clean-u89k.onrender.com/webhooks/fastspring/check?email=EMAIL`);
  console.log(`🔓 Manual activation: POST https://backend-clean-u89k.onrender.com/webhooks/fastspring/activate`);
});
