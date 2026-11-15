// Confirms a TheDaveka Quotes Premium purchase with Google Play (server-side verification,
// as Google recommends). The app sends only the purchase token; nothing is stored or logged.
// Needs the Vercel environment variable GOOGLE_PLAY_SERVICE_ACCOUNT (the service-account JSON key).
const crypto = require('crypto');

const PACKAGE = 'com.thedaveka.quotes';
const PRODUCT = 'premium';
const ACTIVE_STATES = ['SUBSCRIPTION_STATE_ACTIVE', 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD'];
let cachedToken = null;

const b64url = (x) => Buffer.from(x).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

async function accessToken(sa) {
  if (cachedToken && cachedToken.exp > Date.now() + 60_000) return cachedToken.value;
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64url(JSON.stringify({
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/androidpublisher',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  }));
  const sig = crypto.createSign('RSA-SHA256').update(head + '.' + claim).sign(sa.private_key);
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: head + '.' + claim + '.' + b64url(sig),
    }),
  });
  if (!r.ok) throw new Error('token ' + r.status);
  const j = await r.json();
  cachedToken = { value: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return cachedToken.value;
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });

  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  const token = body && body.purchaseToken;
  if (typeof token !== 'string' || token.length < 10 || token.length > 4096 || !/^[A-Za-z0-9._\-:]+$/.test(token)) {
    return res.status(400).json({ error: 'bad_request' });
  }
  if (body.packageName !== undefined && body.packageName !== PACKAGE) return res.status(400).json({ error: 'bad_request' });

  const raw = process.env.GOOGLE_PLAY_SERVICE_ACCOUNT;
  if (!raw) return res.status(503).json({ error: 'not_configured' });

  try {
    const sa = JSON.parse(raw);
    const at = await accessToken(sa);
    const url = 'https://androidpublisher.googleapis.com/androidpublisher/v3/applications/' + PACKAGE +
      '/purchases/subscriptionsv2/tokens/' + encodeURIComponent(token);
    const r = await fetch(url, { headers: { authorization: 'Bearer ' + at } });
    if (r.status === 400 || r.status === 404 || r.status === 410) return res.status(200).json({ active: false, reason: 'unknown_token' });
    if (!r.ok) return res.status(502).json({ error: 'google_unavailable' });
    const s = await r.json();
    const items = (s.lineItems || []).filter((li) => li.productId === PRODUCT);
    const expiry = items.reduce((m, li) => Math.max(m, Date.parse(li.expiryTime || '') || 0), 0);
    const active = ACTIVE_STATES.includes(s.subscriptionState) && items.length > 0 && expiry > Date.now();
    return res.status(200).json({
      active,
      state: s.subscriptionState || null,
      expiry: expiry ? new Date(expiry).toISOString() : null,
      testPurchase: Boolean(s.testPurchase),
    });
  } catch (e) {
    return res.status(502).json({ error: 'verify_failed' });
  }
};
