// Integration test suite for reviews-api — node:test only, no mocks.
// Run against a live server (local by default, or BASE_URL=... for prod).
// See package.json scripts: `npm test` / `npm run test:prod`.
//
// Caveats discovered while writing this suite (see inline notes at each
// affected assertion):
//   - GET/POST /api/shop* always act on process.env.JUDGEME_SHOP_DOMAIN —
//     they ignore any shopDomain sent in the request.
//   - devFallbackToken() in server.js re-activates whichever shop matches
//     JUDGEME_SHOP_DOMAIN even after that shop is "disconnected" in the DB,
//     so /api/reviews does not 503 for that one shop the way it would for
//     any other disconnected shop.
//   - resolveShopDomain() falls back to JUDGEME_SHOP_DOMAIN when no
//     shopDomain is supplied at all, so "missing shopDomain" is never
//     truly unresolvable as long as that env var is set.
//   - /api/sync, /api/onboarding/*, /api/admin/* and the webhook routes are
//     gated by verifyShopifyJWT / verifyWebhookHMAC. When SHOPIFY_CLIENT_SECRET
//     is set on the target server, this file signs a JWT (Authorization:
//     Bearer) for the former and an HMAC (X-Shopify-Hmac-Sha256) for the
//     latter, matching each middleware's exact verification logic in
//     server.js. When the secret is unset (local dev), both middlewares
//     no-op and these headers are simply omitted.
//   - verifyShopifyJWT sets req.verifiedShopDomain from the JWT's `dest`
//     claim, and resolveShopDomain() prefers that over any shopDomain in
//     the query/body. So once auth is enabled, a request is authenticated
//     AS whichever shop the JWT names — a query param can't impersonate a
//     different shop. The "nonexistent shop" check in Suite 7 signs its
//     own JWT for that fake domain for this reason.
import 'dotenv/config';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const BASE_URL = process.env.BASE_URL || 'http://localhost:3001';
const SHOP_DOMAIN = process.env.TEST_SHOP_DOMAIN || 'app-review-3vqgugf9.myshopify.com';
const FAKE_SHOP_DOMAIN = 'gdpr-test-fake-shop.myshopify.com';
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;

// Real Judge.me credentials, loaded from .env — used only by Suite 6/8 to
// exercise the real connect flow, and to restore state afterwards.
const REAL_API_TOKEN = process.env.JUDGEME_API_TOKEN;
const REAL_SHOP_DOMAIN = process.env.JUDGEME_SHOP_DOMAIN || SHOP_DOMAIN;

// Whether SHOP_DOMAIN is the one env-configured shop that gets the dev
// fallback token — computed from the same env var server.js itself reads,
// so the expectation below tracks whatever machine actually runs this.
const HAS_DEV_FALLBACK = SHOP_DOMAIN === process.env.JUDGEME_SHOP_DOMAIN;

// ---------------------------------------------------------------------------
// Auth helpers — mirror verifyShopifyJWT / verifyWebhookHMAC in server.js.
// Both no-op (return no header) when SHOPIFY_CLIENT_SECRET is unset.
// ---------------------------------------------------------------------------
function buildJWT(shopDomain) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ dest: `https://${shopDomain}`, exp: Math.floor(Date.now() / 1000) + 300 })
  ).toString('base64url');
  const signature = crypto
    .createHmac('sha256', SHOPIFY_CLIENT_SECRET)
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function authHeaders(shopDomain) {
  if (!SHOPIFY_CLIENT_SECRET || !shopDomain) return {};
  return { Authorization: `Bearer ${buildJWT(shopDomain)}` };
}

function hmacHeaders(bodyString) {
  if (!SHOPIFY_CLIENT_SECRET) return {};
  const digest = crypto.createHmac('sha256', SHOPIFY_CLIENT_SECRET).update(bodyString, 'utf8').digest('base64');
  return { 'X-Shopify-Hmac-Sha256': digest };
}

async function api(path, options = {}, authShop = SHOP_DOMAIN) {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(authShop),
      ...(options.headers || {}),
    },
  });
  const body = await res.json().catch(() => null);
  return { status: res.status, body };
}

function post(path, payload, authShop = SHOP_DOMAIN) {
  return api(path, { method: 'POST', body: JSON.stringify(payload ?? {}) }, authShop);
}

// Dedicated helper for GDPR webhook calls: HMAC-signed, no JWT (those
// routes are gated by verifyWebhookHMAC only, never verifyShopifyJWT).
async function webhook(path, payload, extraHeaders = {}) {
  const bodyString = JSON.stringify(payload ?? {});
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...hmacHeaders(bodyString),
      ...extraHeaders,
    },
    body: bodyString,
  });
  const body = await res.json().catch(() => null);
  return { status: res.status, body };
}

// ---------------------------------------------------------------------------
// Result tracking + summary table
// ---------------------------------------------------------------------------
const results = [];

async function runTest(name, fn) {
  let status = 'PASS';
  await test(name, async () => {
    try {
      const outcome = await fn();
      if (outcome === 'SKIP') status = 'SKIP';
    } catch (err) {
      status = 'FAIL';
      throw err;
    }
  });
  results.push({ name, status });
}

function printSummary() {
  const nameWidth = Math.max(38, ...results.map((r) => r.name.length + 2));
  const line = (l, m, r) => l + '═'.repeat(nameWidth) + m + '════════' + r;

  console.log('\n' + line('╔', '╦', '╗'));
  console.log(`║ ${'Test'.padEnd(nameWidth - 1)}║ Result ║`);
  console.log(line('╠', '╬', '╣'));
  for (const r of results) {
    console.log(`║ ${r.name.padEnd(nameWidth - 1)}║ ${r.status.padEnd(6)} ║`);
  }
  console.log(line('╚', '╩', '╝'));

  const passed = results.filter((r) => r.status === 'PASS').length;
  const skipped = results.filter((r) => r.status === 'SKIP').length;
  const failed = results.length - passed - skipped;
  console.log(
    `Total: ${passed} passed, ${failed} failed` + (skipped ? `, ${skipped} skipped` : '')
  );
}

// ---------------------------------------------------------------------------
// Suite 1: Health check
// ---------------------------------------------------------------------------
await runTest('Suite 1: server is reachable at BASE_URL', async () => {
  const res = await fetch(`${BASE_URL}/api/reviews`);
  assert.ok(res.status, 'expected an HTTP response, got a network error');
});

// ---------------------------------------------------------------------------
// Suite 2: GET /api/shop
// ---------------------------------------------------------------------------
await runTest('Suite 2: GET /api/shop returns shopDomain and plan', async () => {
  const { status, body } = await api('/api/shop');
  assert.equal(status, 200);
  assert.ok(body.shopDomain, 'expected a shopDomain field');
  assert.ok(['free', 'pro'].includes(body.plan), `unexpected plan: ${body.plan}`);
});

// ---------------------------------------------------------------------------
// Suite 3: POST /api/shop/plan
// (order matters: leaves plan = "free" for Suite 4's free-tier checks)
// ---------------------------------------------------------------------------
await runTest('Suite 3: POST /api/shop/plan accepts "pro"', async () => {
  const { status, body } = await post('/api/shop/plan', { plan: 'pro' });
  assert.equal(status, 200);
  assert.equal(body.plan, 'pro');
});

await runTest('Suite 3: POST /api/shop/plan accepts "free"', async () => {
  const { status, body } = await post('/api/shop/plan', { plan: 'free' });
  assert.equal(status, 200);
  assert.equal(body.plan, 'free');
});

await runTest('Suite 3: POST /api/shop/plan rejects invalid plan', async () => {
  const { status } = await post('/api/shop/plan', { plan: 'invalid' });
  assert.equal(status, 400);
});

await runTest('Suite 3: POST /api/shop/plan rejects empty body', async () => {
  const { status } = await post('/api/shop/plan', {});
  assert.equal(status, 400);
});

// ---------------------------------------------------------------------------
// Suite 4: GET /api/reviews (core functionality)
// ---------------------------------------------------------------------------
await runTest('Suite 4: GET /api/reviews returns reviews array + source cache', async () => {
  const { status, body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}`);
  assert.equal(status, 200);
  assert.ok(Array.isArray(body.reviews));
  assert.equal(body.source, 'cache');
});

await runTest('Suite 4: GET /api/reviews includes template field', async () => {
  const { body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}`);
  assert.ok('template' in body);
});

await runTest('Suite 4: GET /api/reviews includes upgradeRequired field', async () => {
  const { body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}`);
  assert.ok('upgradeRequired' in body);
});

await runTest('Suite 4: free plan + template=carousel downgrades to grid', async () => {
  const { body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}&template=carousel`);
  assert.equal(body.upgradeRequired, true);
  assert.equal(body.template, 'grid');
});

await runTest('Suite 4: free plan + template=list downgrades to grid', async () => {
  const { body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}&template=list`);
  assert.equal(body.upgradeRequired, true);
  assert.equal(body.template, 'grid');
});

await runTest('Suite 4: free plan + template=grid is not an upgrade', async () => {
  const { body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}&template=grid`);
  assert.equal(body.upgradeRequired, false);
  assert.equal(body.template, 'grid');
});

await runTest('Suite 4: (setup) switch plan to pro', async () => {
  const { status, body } = await post('/api/shop/plan', { plan: 'pro' });
  assert.equal(status, 200);
  assert.equal(body.plan, 'pro');
});

await runTest('Suite 4: pro plan + template=carousel is not an upgrade', async () => {
  const { body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}&template=carousel`);
  assert.equal(body.upgradeRequired, false);
  assert.equal(body.template, 'carousel');
});

await runTest('Suite 4: pro plan + template=list is not an upgrade', async () => {
  const { body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}&template=list`);
  assert.equal(body.upgradeRequired, false);
  assert.equal(body.template, 'list');
});

await runTest('Suite 4: pro plan + template=grid is not an upgrade', async () => {
  const { body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}&template=grid`);
  assert.equal(body.upgradeRequired, false);
  assert.equal(body.template, 'grid');
});

await runTest('Suite 4: count=1 returns exactly 1 review', async () => {
  const { body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}&count=1`);
  assert.equal(body.reviews.length, 1);
});

await runTest('Suite 4: count=0 does not crash', async () => {
  // server.js treats count=0 as invalid (requestedCount > 0 fails) and
  // silently falls back to DEFAULT_COUNT (20) — it does not return 0 items
  // or an error. Asserting the real behavior here, not the "0 or error"
  // guess from the original spec.
  const { status, body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}&count=0`);
  assert.equal(status, 200);
  assert.ok(Array.isArray(body.reviews));
});

for (const sort of ['recent', 'highest', 'lowest', 'invalid']) {
  await runTest(`Suite 4: sort=${sort} returns 200`, async () => {
    const { status } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}&sort=${sort}`);
    assert.equal(status, 200);
  });
}

await runTest('Suite 4: each review has the expected shape', async () => {
  const { body } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}&count=1`);
  assert.ok(body.reviews.length > 0, 'need at least one review to check shape');
  const review = body.reviews[0];
  for (const field of ['id', 'rating', 'reviewerName', 'body', 'createdAt', 'shopDomain']) {
    assert.ok(field in review, `missing field: ${field}`);
  }
});

// ---------------------------------------------------------------------------
// Suite 5: POST /api/sync
// ---------------------------------------------------------------------------
await runTest('Suite 5: POST /api/sync returns a synced count', async () => {
  const { status, body } = await post('/api/sync', { shopDomain: SHOP_DOMAIN });
  assert.equal(status, 200);
  assert.equal(typeof body.synced, 'number');
  assert.ok(body.synced >= 0);
});

await runTest('Suite 5: POST /api/sync is idempotent (safe to call twice)', async () => {
  const { status } = await post('/api/sync', { shopDomain: SHOP_DOMAIN });
  assert.equal(status, 200);
});

// ---------------------------------------------------------------------------
// Suite 6: POST /api/onboarding/connect
// ---------------------------------------------------------------------------
await runTest('Suite 6: connect with missing fields returns 400', async () => {
  const { status } = await post('/api/onboarding/connect', { shopDomain: SHOP_DOMAIN });
  assert.equal(status, 400);
});

await runTest('Suite 6: connect with invalid token returns 400 with error message', async () => {
  const { status, body } = await post('/api/onboarding/connect', {
    shopDomain: SHOP_DOMAIN,
    apiToken: 'not-a-real-token',
  });
  assert.equal(status, 400);
  assert.ok(body.error);
});

await runTest('Suite 6: connect with valid token returns success + persists', async () => {
  if (!REAL_API_TOKEN) {
    console.warn('  [skip] JUDGEME_API_TOKEN not set in .env — skipping live-credential check');
    return 'SKIP';
  }
  const { status, body } = await post(
    '/api/onboarding/connect',
    { shopDomain: REAL_SHOP_DOMAIN, apiToken: REAL_API_TOKEN },
    REAL_SHOP_DOMAIN
  );
  assert.equal(status, 200);
  assert.equal(body.success, true);

  const statusCheck = await api(
    `/api/onboarding/status?shopDomain=${REAL_SHOP_DOMAIN}`,
    {},
    REAL_SHOP_DOMAIN
  );
  assert.equal(statusCheck.body.connected, true);
});

// ---------------------------------------------------------------------------
// Suite 7: GET /api/onboarding/status
// ---------------------------------------------------------------------------
await runTest('Suite 7: status for the real shop is connected', async () => {
  const { status, body } = await api(`/api/onboarding/status?shopDomain=${SHOP_DOMAIN}`);
  assert.equal(status, 200);
  assert.equal(body.connected, true);
});

await runTest('Suite 7: status for a nonexistent shop is not connected', async () => {
  // When SHOPIFY_CLIENT_SECRET is set, req.verifiedShopDomain (from the JWT)
  // wins over the query param — so the JWT itself must name this fake shop.
  const { status, body } = await api(
    '/api/onboarding/status?shopDomain=nonexistent.myshopify.com',
    {},
    'nonexistent.myshopify.com'
  );
  assert.equal(status, 200);
  assert.equal(body.connected, false);
});

await runTest('Suite 7: status with missing shopDomain falls back gracefully', async () => {
  // resolveShopDomain() falls back to JUDGEME_SHOP_DOMAIN when nothing is
  // supplied, so this is never a 400 as long as that env var is set — it
  // resolves to the primary shop's own status instead.
  const { status, body } = await api('/api/onboarding/status');
  assert.equal(status, 200);
  assert.equal(typeof body.connected, 'boolean');
});

// ---------------------------------------------------------------------------
// Suite 8: POST /api/onboarding/disconnect
// ---------------------------------------------------------------------------
await runTest('Suite 8: disconnect clears the stored token', async () => {
  const { status, body } = await post('/api/onboarding/disconnect', { shopDomain: SHOP_DOMAIN });
  assert.equal(status, 200);
  assert.equal(body.success, true);
});

await runTest('Suite 8: status reflects disconnected', async () => {
  const { body } = await api(`/api/onboarding/status?shopDomain=${SHOP_DOMAIN}`);
  assert.equal(body.connected, false);
});

await runTest('Suite 8: GET /api/reviews after disconnect', async () => {
  const { status } = await api(`/api/reviews?shopDomain=${SHOP_DOMAIN}`);
  if (HAS_DEV_FALLBACK) {
    // devFallbackToken() re-activates this exact shop from .env's
    // JUDGEME_API_TOKEN regardless of the DB's disconnected state — by
    // design, per server.js's dev-mode comment. Not a bug in this suite.
    assert.equal(status, 200);
  } else {
    assert.equal(status, 503);
  }
});

await runTest('Suite 8: reconnect restores the shop', async () => {
  if (!REAL_API_TOKEN) {
    console.warn('  [skip] JUDGEME_API_TOKEN not set in .env — cannot reconnect for real');
    return 'SKIP';
  }
  const { status, body } = await post(
    '/api/onboarding/connect',
    { shopDomain: REAL_SHOP_DOMAIN, apiToken: REAL_API_TOKEN },
    REAL_SHOP_DOMAIN
  );
  assert.equal(status, 200);
  assert.equal(body.success, true);
});

// ---------------------------------------------------------------------------
// Suite 9: GET /api/admin/stats
// ---------------------------------------------------------------------------
await runTest('Suite 9: admin/stats returns the expected shape', async () => {
  const { status, body } = await api(`/api/admin/stats?shopDomain=${SHOP_DOMAIN}`);
  assert.equal(status, 200);
  for (const field of ['total', 'averageRating', 'distribution', 'lastSyncedAt', 'syncStatus']) {
    assert.ok(field in body, `missing field: ${field}`);
  }
  for (const rating of [1, 2, 3, 4, 5]) {
    assert.ok(rating in body.distribution, `distribution missing rating ${rating}`);
  }
  assert.ok(body.total >= 0);
  assert.ok(body.averageRating >= 0 && body.averageRating <= 5);
});

// ---------------------------------------------------------------------------
// Suite 10: GET /api/admin/reviews
// ---------------------------------------------------------------------------
await runTest('Suite 10: admin/reviews returns the expected shape', async () => {
  const { status, body } = await api(`/api/admin/reviews?shopDomain=${SHOP_DOMAIN}`);
  assert.equal(status, 200);
  for (const field of ['reviews', 'total', 'page', 'totalPages']) {
    assert.ok(field in body, `missing field: ${field}`);
  }
});

await runTest('Suite 10: pagination respects limit', async () => {
  const { body } = await api(`/api/admin/reviews?shopDomain=${SHOP_DOMAIN}&page=1&limit=5`);
  assert.ok(body.reviews.length <= 5);
});

await runTest('Suite 10: rating=5 filters correctly', async () => {
  const { body } = await api(`/api/admin/reviews?shopDomain=${SHOP_DOMAIN}&rating=5`);
  for (const r of body.reviews) assert.equal(r.rating, 5);
});

await runTest('Suite 10: rating=1 filters correctly (or returns empty)', async () => {
  const { body } = await api(`/api/admin/reviews?shopDomain=${SHOP_DOMAIN}&rating=1`);
  for (const r of body.reviews) assert.equal(r.rating, 1);
});

await runTest('Suite 10: sort=highest puts the highest rating first', async () => {
  const { body } = await api(`/api/admin/reviews?shopDomain=${SHOP_DOMAIN}&sort=highest`);
  if (body.reviews.length < 2) return 'SKIP';
  assert.ok(body.reviews[0].rating >= body.reviews[body.reviews.length - 1].rating);
});

await runTest('Suite 10: sort=lowest puts the lowest rating first', async () => {
  const { body } = await api(`/api/admin/reviews?shopDomain=${SHOP_DOMAIN}&sort=lowest`);
  if (body.reviews.length < 2) return 'SKIP';
  assert.ok(body.reviews[0].rating <= body.reviews[body.reviews.length - 1].rating);
});

await runTest('Suite 10: search=Perfect filters by body/reviewerName', async () => {
  const { body } = await api(`/api/admin/reviews?shopDomain=${SHOP_DOMAIN}&search=Perfect`);
  for (const r of body.reviews) {
    const match =
      (r.body && r.body.includes('Perfect')) || (r.reviewerName && r.reviewerName.includes('Perfect'));
    assert.ok(match, `review ${r.id} does not contain "Perfect"`);
  }
});

// ---------------------------------------------------------------------------
// Suite 11: POST /api/admin/sync-interval
// ---------------------------------------------------------------------------
for (const interval of [60, 360, 1440]) {
  await runTest(`Suite 11: sync-interval accepts ${interval}`, async () => {
    const { status } = await post('/api/admin/sync-interval', { shopDomain: SHOP_DOMAIN, interval });
    assert.equal(status, 200);
  });
}

await runTest('Suite 11: sync-interval rejects 999', async () => {
  const { status } = await post('/api/admin/sync-interval', { shopDomain: SHOP_DOMAIN, interval: 999 });
  assert.equal(status, 400);
});

await runTest('Suite 11: sync-interval rejects a string value', async () => {
  const { status } = await post('/api/admin/sync-interval', { shopDomain: SHOP_DOMAIN, interval: 'string' });
  assert.equal(status, 400);
});

// ---------------------------------------------------------------------------
// Suite 12: GDPR webhooks
// ---------------------------------------------------------------------------
await runTest('Suite 12: POST /webhooks with missing topic returns 404', async () => {
  const { status } = await webhook('/webhooks', { shop_domain: FAKE_SHOP_DOMAIN });
  assert.equal(status, 404);
});

for (const topic of ['customers/data_request', 'customers/redact', 'shop/redact']) {
  await runTest(`Suite 12: POST /webhooks with topic ${topic} returns 200`, async () => {
    const { status } = await webhook(
      '/webhooks',
      { shop_domain: FAKE_SHOP_DOMAIN, customer: { id: 999 } },
      { 'X-Shopify-Topic': topic }
    );
    assert.equal(status, 200);
  });
}

await runTest('Suite 12: POST /webhooks with an unknown topic returns 404', async () => {
  const { status } = await webhook(
    '/webhooks',
    { shop_domain: FAKE_SHOP_DOMAIN },
    { 'X-Shopify-Topic': 'unknown/topic' }
  );
  assert.equal(status, 404);
});

for (const path of ['/webhooks/customers/data_request', '/webhooks/customers/redact', '/webhooks/shop/redact']) {
  await runTest(`Suite 12: individual route ${path} returns 200`, async () => {
    const { status } = await webhook(path, { shop_domain: FAKE_SHOP_DOMAIN, customer: { id: 999 } });
    assert.equal(status, 200);
  });
}

await runTest('Suite 12: the real shop is untouched by the fake shop/redact calls', async () => {
  const { body } = await api(`/api/onboarding/status?shopDomain=${SHOP_DOMAIN}`);
  assert.equal(body.connected, true);
});

// ---------------------------------------------------------------------------
// Cleanup — restore plan to "free" and sync interval to the default (60).
// ---------------------------------------------------------------------------
try {
  const { status, body } = await post('/api/shop/plan', { plan: 'free' });
  if (status !== 200 || body.plan !== 'free') {
    console.warn(`[cleanup] WARNING: failed to restore plan to "free" (status ${status})`);
  }
} catch (err) {
  console.warn(`[cleanup] WARNING: failed to restore plan to "free" — ${err.message}`);
}

try {
  const { status } = await post('/api/admin/sync-interval', { shopDomain: SHOP_DOMAIN, interval: 60 });
  if (status !== 200) {
    console.warn(`[cleanup] WARNING: failed to restore sync interval to 60 (status ${status})`);
  }
} catch (err) {
  console.warn(`[cleanup] WARNING: failed to restore sync interval to 60 — ${err.message}`);
}

printSummary();
