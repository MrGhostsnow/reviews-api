// server.js
// Express server that serves normalized review data to the storefront block.
//
// Two responsibilities:
// 1. GET /api/reviews  — serves cached reviews from SQLite (fast, no Judge.me call)
// 2. POST /api/sync    — pulls fresh data from Judge.me and upserts into SQLite
//
// In production, /api/sync should be called by a cron job or webhook,
// not on every storefront request.

require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3001;

const JUDGEME_API_BASE = "https://api.judge.me/api/v1";

const DB_PATH = (process.env.DATABASE_URL || "file:./reviews.db").replace(/^file:/, "");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS Review (
    id                   TEXT    NOT NULL,
    shopDomain           TEXT    NOT NULL,
    sourceProvider       TEXT,
    sourceReviewId       INTEGER,
    productExternalId    INTEGER,
    rating               INTEGER,
    title                TEXT,
    body                 TEXT,
    reviewerName         TEXT,
    photos               TEXT    DEFAULT '[]',
    hasPublishedPictures  INTEGER DEFAULT 0,
    hasPublishedVideos    INTEGER DEFAULT 0,
    verifiedBuyerStatus  TEXT,
    createdAt            TEXT,
    syncedAt             TEXT    DEFAULT (datetime('now')),
    PRIMARY KEY (shopDomain, sourceProvider, sourceReviewId)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS Shop (
    shopDomain      TEXT PRIMARY KEY,
    plan            TEXT NOT NULL DEFAULT 'free',
    judgemApiToken  TEXT,
    syncInterval    INTEGER DEFAULT 60,
    createdAt       TEXT DEFAULT (datetime('now')),
    updatedAt       TEXT DEFAULT (datetime('now'))
  )
`);

// Existing databases predate the syncInterval column — add it if missing
// rather than dropping the table (Shop rows hold real merchant tokens).
const shopColumns = db.prepare("PRAGMA table_info(Shop)").all().map((c) => c.name);
if (!shopColumns.includes("syncInterval")) {
  db.exec("ALTER TABLE Shop ADD COLUMN syncInterval INTEGER DEFAULT 60");
}

db.prepare(`INSERT OR IGNORE INTO Shop (shopDomain, judgemApiToken, plan)
  VALUES (?, ?, 'free')`).run(
  process.env.JUDGEME_SHOP_DOMAIN,
  process.env.JUDGEME_API_TOKEN
);

app.use(cors({ origin: "*", methods: ["GET", "POST"] }));
// verify captures the raw bytes for webhook HMAC checks without double-consuming
// the request stream (a second raw-body reader before this would starve body-parser).
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

// ---------------------------------------------------------------------------
// Shop lookups — every route resolves the shop from the request, falling
// back to JUDGEME_SHOP_DOMAIN/JUDGEME_API_TOKEN so local dev keeps working
// without going through the onboarding UI.
// ---------------------------------------------------------------------------
const getShopFullStmt = db.prepare("SELECT * FROM Shop WHERE shopDomain = ?");
const upsertShopTokenStmt = db.prepare(`
  INSERT INTO Shop (shopDomain, judgemApiToken, plan)
  VALUES (?, ?, 'free')
  ON CONFLICT(shopDomain) DO UPDATE SET judgemApiToken = excluded.judgemApiToken, updatedAt = datetime('now')
`);
const disconnectShopStmt = db.prepare(
  "UPDATE Shop SET judgemApiToken = NULL, updatedAt = datetime('now') WHERE shopDomain = ?"
);
const reviewCountStmt = db.prepare("SELECT COUNT(*) as count FROM Review WHERE shopDomain = ?");
const lastSyncedStmt = db.prepare(
  "SELECT MAX(syncedAt) as lastSyncedAt FROM Review WHERE shopDomain = ?"
);

function resolveShopDomain(req) {
  return (
    req.verifiedShopDomain ||
    req.headers["x-shopify-shop-domain"] ||
    req.query.shop ||
    req.query.shopDomain ||
    req.body?.shopDomain ||
    process.env.JUDGEME_SHOP_DOMAIN
  );
}

// Verifies the Shopify session token (JWT) App Bridge attaches to embedded
// app requests, so shopDomain can't be spoofed by the client. Skipped in dev
// when SHOPIFY_CLIENT_SECRET isn't set.
function verifyShopifyJWT(req, res, next) {
  if (!process.env.SHOPIFY_CLIENT_SECRET) {
    return next();
  }

  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing authorization header" });
  }

  const token = authHeader.slice(7);

  try {
    const [headerB64, payloadB64, signatureB64] = token.split(".");
    if (!headerB64 || !payloadB64 || !signatureB64) {
      throw new Error("Malformed JWT");
    }

    const message = `${headerB64}.${payloadB64}`;
    const expectedSig = crypto
      .createHmac("sha256", process.env.SHOPIFY_CLIENT_SECRET)
      .update(message)
      .digest("base64url");

    if (expectedSig !== signatureB64) {
      throw new Error("Invalid signature");
    }

    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());

    if (payload.exp && Date.now() / 1000 > payload.exp) {
      throw new Error("Token expired");
    }

    const dest = payload.dest || "";
    const shopDomain = dest.replace("https://", "");
    if (!shopDomain.endsWith(".myshopify.com")) {
      throw new Error("Invalid dest claim");
    }

    req.verifiedShopDomain = shopDomain;
    next();
  } catch (err) {
    return res.status(401).json({ error: `Unauthorized: ${err.message}` });
  }
}

// Only falls back to the .env token for local dev calls — never for
// requests arriving through Shopify's App Proxy (identified by the
// x-shopify-shop-domain header it adds), so a disconnected shop in
// production gets a real 503 instead of silently borrowing the .env
// token configured for a different (dev) shop.
function devFallbackToken(req, shopDomain) {
  if (req.headers["x-shopify-shop-domain"]) return undefined;
  return shopDomain === process.env.JUDGEME_SHOP_DOMAIN
    ? process.env.JUDGEME_API_TOKEN
    : undefined;
}

let isSyncing = false;

// ---------------------------------------------------------------------------
// Normalization (same logic as connector.js, kept in sync)
// ---------------------------------------------------------------------------
function normalizeReview(raw, shopDomain) {
  return {
    id: `judge_me_${raw.id}`,
    shopDomain,
    sourceProvider: "judge_me",
    sourceReviewId: raw.id,
    productExternalId: raw.product_external_id ?? null,
    rating: raw.rating,
    title: raw.title ?? null,
    body: raw.body ?? null,
    reviewerName: raw.reviewer?.name ?? null,
    photos: JSON.stringify(
      (raw.pictures ?? [])
        .map((p) => p.url ?? p.urls?.original)
        .filter(Boolean)
    ),
    hasPublishedPictures: raw.has_published_pictures ?? false,
    hasPublishedVideos: raw.has_published_videos ?? false,
    verifiedBuyerStatus: raw.verified_buyer ?? null,
    createdAt: raw.created_at ?? null,
    // Deliberately NOT copying raw.reviewer.tags or other reviewer fields:
    // not needed for display, and may carry unrelated third-party CRM data.
  };
}

const upsertReviewStmt = db.prepare(`
  INSERT INTO Review (
    id, shopDomain, sourceProvider, sourceReviewId, productExternalId, rating,
    title, body, reviewerName, photos, hasPublishedPictures,
    hasPublishedVideos, verifiedBuyerStatus, createdAt, syncedAt
  ) VALUES (
    @id, @shopDomain, @sourceProvider, @sourceReviewId, @productExternalId, @rating,
    @title, @body, @reviewerName, @photos, @hasPublishedPictures,
    @hasPublishedVideos, @verifiedBuyerStatus, @createdAt, datetime('now')
  )
  ON CONFLICT (shopDomain, sourceProvider, sourceReviewId) DO UPDATE SET
    id = excluded.id,
    productExternalId = excluded.productExternalId,
    rating = excluded.rating,
    title = excluded.title,
    body = excluded.body,
    reviewerName = excluded.reviewerName,
    photos = excluded.photos,
    hasPublishedPictures = excluded.hasPublishedPictures,
    hasPublishedVideos = excluded.hasPublishedVideos,
    verifiedBuyerStatus = excluded.verifiedBuyerStatus,
    createdAt = excluded.createdAt,
    syncedAt = datetime('now')
`);

function upsertReview(normalized) {
  upsertReviewStmt.run({
    ...normalized,
    hasPublishedPictures: normalized.hasPublishedPictures ? 1 : 0,
    hasPublishedVideos: normalized.hasPublishedVideos ? 1 : 0,
  });
}

// ---------------------------------------------------------------------------
// GET /api/reviews — serves from SQLite cache
// ---------------------------------------------------------------------------
const TEMPLATES = new Set(["grid", "carousel", "list"]);
const FREE_TEMPLATES = new Set(["grid"]);
const SORT_ORDER_BY = {
  recent: "createdAt DESC",
  highest: "rating DESC",
  lowest: "rating ASC",
};
const DEFAULT_COUNT = 20;
const MAX_COUNT = 20;

app.get("/api/reviews", (req, res) => {
  try {
    const shopDomain = resolveShopDomain(req);
    const shop = getShopFullStmt.get(shopDomain);
    const apiToken = shop?.judgemApiToken || devFallbackToken(req, shopDomain);

    if (!apiToken) {
      return res
        .status(503)
        .json({ error: "Shop not configured. Please complete onboarding." });
    }

    const plan = shop?.plan ?? "free";

    const requestedTemplate = TEMPLATES.has(req.query.template)
      ? req.query.template
      : "grid";
    const upgradeRequired = plan === "free" && !FREE_TEMPLATES.has(requestedTemplate);
    const template = upgradeRequired ? "grid" : requestedTemplate;

    const sort = Object.prototype.hasOwnProperty.call(SORT_ORDER_BY, req.query.sort)
      ? req.query.sort
      : "recent";
    const orderBy = SORT_ORDER_BY[sort];

    const requestedCount = parseInt(req.query.count, 10);
    const count =
      Number.isInteger(requestedCount) && requestedCount > 0
        ? Math.min(requestedCount, MAX_COUNT)
        : DEFAULT_COUNT;

    const conditions = ["shopDomain = ?"];
    const params = [shopDomain];

    const productId = parseInt(req.query.productId, 10);
    if (Number.isInteger(productId) && productId > 0) {
      conditions.push("productExternalId = ?");
      params.push(productId);
    }

    const whereClause = conditions.join(" AND ");

    const reviews = db
      .prepare(`SELECT * FROM Review WHERE ${whereClause} ORDER BY ${orderBy} LIMIT ?`)
      .all(...params, count);

    const formatted = reviews.map((r) => ({
      ...r,
      photos: JSON.parse(r.photos),
      hasPublishedPictures: !!r.hasPublishedPictures,
      hasPublishedVideos: !!r.hasPublishedVideos,
    }));

    res.json({
      reviews: formatted,
      source: "cache",
      template,
      upgradeRequired,
      sort,
      plan,
    });
  } catch (err) {
    console.error("Error reading from database:", err.message);
    res.status(500).json({ error: "Failed to read reviews from database" });
  }
});

// ---------------------------------------------------------------------------
// GET /api/shop — current shop's plan
// POST /api/shop/plan — update the shop's plan
// ---------------------------------------------------------------------------
const getShopStmt = db.prepare("SELECT shopDomain, plan FROM Shop WHERE shopDomain = ?");
const updateShopPlanStmt = db.prepare(
  "UPDATE Shop SET plan = ?, updatedAt = datetime('now') WHERE shopDomain = ?"
);

app.get("/api/shop", (req, res) => {
  const shop = getShopStmt.get(process.env.JUDGEME_SHOP_DOMAIN);

  if (!shop) {
    return res.status(404).json({ error: "Shop not found" });
  }

  res.json(shop);
});

app.post("/api/shop/plan", (req, res) => {
  const { plan } = req.body ?? {};

  if (plan !== "free" && plan !== "pro") {
    return res.status(400).json({ error: "plan must be 'free' or 'pro'" });
  }

  const shopDomain = process.env.JUDGEME_SHOP_DOMAIN;
  const result = updateShopPlanStmt.run(plan, shopDomain);

  if (result.changes === 0) {
    return res.status(404).json({ error: "Shop not found" });
  }

  res.json({ shopDomain, plan });
});

// ---------------------------------------------------------------------------
// POST /api/onboarding/connect — verify a Judge.me token and save it
// GET  /api/onboarding/status  — connection state for the app-home UI
// POST /api/onboarding/disconnect — clear the saved token
// ---------------------------------------------------------------------------
app.post("/api/onboarding/connect", verifyShopifyJWT, async (req, res) => {
  const shopDomain = resolveShopDomain(req);
  const { apiToken } = req.body ?? {};

  if (!shopDomain || !apiToken) {
    return res.status(400).json({ error: "shopDomain and apiToken are required" });
  }

  try {
    const params = new URLSearchParams({
      api_token: apiToken,
      shop_domain: shopDomain,
      per_page: "1",
    });
    const testResponse = await fetch(`${JUDGEME_API_BASE}/reviews?${params.toString()}`);

    if (!testResponse.ok) {
      return res.status(400).json({ error: "Invalid token or shop domain" });
    }
  } catch (err) {
    console.error("Judge.me token verification failed:", err.message);
    return res.status(400).json({ error: "Invalid token or shop domain" });
  }

  upsertShopTokenStmt.run(shopDomain, apiToken);
  const shop = getShopFullStmt.get(shopDomain);

  res.json({ success: true, shopDomain, plan: shop.plan });
});

app.get("/api/onboarding/status", verifyShopifyJWT, (req, res) => {
  const shopDomain = resolveShopDomain(req);

  if (!shopDomain) {
    return res.status(400).json({ error: "shopDomain is required" });
  }

  const shop = getShopFullStmt.get(shopDomain);
  const connected = !!shop?.judgemApiToken;

  res.json({
    connected,
    shopDomain,
    plan: shop?.plan ?? "free",
    reviewCount: reviewCountStmt.get(shopDomain).count,
    lastSyncedAt: lastSyncedStmt.get(shopDomain).lastSyncedAt,
    syncInterval: shop?.syncInterval ?? 60,
  });
});

app.post("/api/onboarding/disconnect", verifyShopifyJWT, (req, res) => {
  const shopDomain = resolveShopDomain(req);

  if (!shopDomain) {
    return res.status(400).json({ error: "shopDomain is required" });
  }

  disconnectShopStmt.run(shopDomain);
  res.json({ success: true, shopDomain });
});

// ---------------------------------------------------------------------------
// GET /api/admin/reviews — paginated, filterable review list for the admin UI
// GET /api/admin/stats   — aggregate stats for the dashboard
// POST /api/admin/sync-interval — save + apply the shop's auto-sync cadence
// ---------------------------------------------------------------------------
const ADMIN_DEFAULT_LIMIT = 20;
const ADMIN_MAX_LIMIT = 50;

app.get("/api/admin/reviews", verifyShopifyJWT, (req, res) => {
  try {
    const shopDomain = resolveShopDomain(req);
    if (!shopDomain) {
      return res.status(400).json({ error: "shopDomain is required" });
    }

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const requestedLimit = parseInt(req.query.limit, 10);
    const limit =
      Number.isInteger(requestedLimit) && requestedLimit > 0
        ? Math.min(requestedLimit, ADMIN_MAX_LIMIT)
        : ADMIN_DEFAULT_LIMIT;
    const offset = (page - 1) * limit;

    const conditions = ["shopDomain = ?"];
    const params = [shopDomain];

    const rating = parseInt(req.query.rating, 10);
    if (Number.isInteger(rating) && rating >= 1 && rating <= 5) {
      conditions.push("rating = ?");
      params.push(rating);
    }

    const search = (req.query.search || "").trim();
    if (search) {
      conditions.push("(body LIKE ? OR reviewerName LIKE ?)");
      const like = `%${search}%`;
      params.push(like, like);
    }

    const productId = parseInt(req.query.productId, 10);
    if (Number.isInteger(productId) && productId > 0) {
      conditions.push("productExternalId = ?");
      params.push(productId);
    }

    const whereClause = conditions.join(" AND ");
    const sort = Object.prototype.hasOwnProperty.call(SORT_ORDER_BY, req.query.sort)
      ? req.query.sort
      : "recent";
    const orderBy = SORT_ORDER_BY[sort];

    const total = db
      .prepare(`SELECT COUNT(*) as count FROM Review WHERE ${whereClause}`)
      .get(...params).count;
    const totalPages = Math.max(1, Math.ceil(total / limit));

    const rows = db
      .prepare(`SELECT * FROM Review WHERE ${whereClause} ORDER BY ${orderBy} LIMIT ? OFFSET ?`)
      .all(...params, limit, offset);

    const reviews = rows.map((r) => ({
      ...r,
      photos: JSON.parse(r.photos),
      hasPublishedPictures: !!r.hasPublishedPictures,
      hasPublishedVideos: !!r.hasPublishedVideos,
    }));

    res.json({ reviews, total, page, totalPages });
  } catch (err) {
    console.error("Error reading admin reviews:", err.message);
    res.status(500).json({ error: "Failed to read reviews from database" });
  }
});

app.get("/api/admin/stats", verifyShopifyJWT, (req, res) => {
  const shopDomain = resolveShopDomain(req);
  if (!shopDomain) {
    return res.status(400).json({ error: "shopDomain is required" });
  }

  const ratings = db
    .prepare("SELECT rating FROM Review WHERE shopDomain = ?")
    .all(shopDomain)
    .map((r) => r.rating);

  const total = ratings.length;
  const distribution = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
  let sum = 0;
  for (const rating of ratings) {
    if (rating >= 1 && rating <= 5) distribution[rating]++;
    sum += rating;
  }
  const averageRating = total > 0 ? Math.round((sum / total) * 10) / 10 : 0;

  res.json({
    total,
    averageRating,
    distribution,
    lastSyncedAt: lastSyncedStmt.get(shopDomain).lastSyncedAt,
    syncStatus: isSyncing ? "syncing" : "idle",
  });
});

const ALLOWED_SYNC_INTERVALS = new Set([60, 360, 1440]);
const updateSyncIntervalStmt = db.prepare(
  "UPDATE Shop SET syncInterval = ?, updatedAt = datetime('now') WHERE shopDomain = ?"
);

app.post("/api/admin/sync-interval", verifyShopifyJWT, (req, res) => {
  const shopDomain = resolveShopDomain(req);
  if (!shopDomain) {
    return res.status(400).json({ error: "shopDomain is required" });
  }

  const { interval } = req.body ?? {};
  if (!ALLOWED_SYNC_INTERVALS.has(interval)) {
    return res.status(400).json({ error: "interval must be 60, 360, or 1440" });
  }

  const result = updateSyncIntervalStmt.run(interval, shopDomain);
  if (result.changes === 0) {
    return res.status(404).json({ error: "Shop not found" });
  }

  scheduleAutoSync(interval);
  res.json({ success: true, interval });
});

// ---------------------------------------------------------------------------
// syncReviews — pulls from Judge.me and upserts into SQLite
// ---------------------------------------------------------------------------
async function syncReviews(shopDomain, apiToken) {
  let page = 1;
  let totalSynced = 0;
  let hasMore = true;

  while (hasMore) {
    const params = new URLSearchParams({
      api_token: apiToken,
      shop_domain: shopDomain,
      per_page: "100",
      page: String(page),
    });

    const response = await fetch(`${JUDGEME_API_BASE}/reviews?${params.toString()}`);

    if (!response.ok) {
      throw new Error(`Judge.me API returned ${response.status}`);
    }

    const data = await response.json();
    const reviews = data.reviews ?? [];

    if (reviews.length === 0) {
      hasMore = false;
      break;
    }

    // Upsert each review — insert if new, update if already exists
    for (const raw of reviews) {
      upsertReview(normalizeReview(raw, shopDomain));
    }

    totalSynced += reviews.length;
    page++;

    // Judge.me returns fewer than per_page when on the last page
    if (reviews.length < 100) {
      hasMore = false;
    }
  }

  console.log(`Sync complete: ${totalSynced} reviews upserted.`);
  return totalSynced;
}

// ---------------------------------------------------------------------------
// POST /api/sync — triggers syncReviews() on demand
// ---------------------------------------------------------------------------
app.post("/api/sync", verifyShopifyJWT, async (req, res) => {
  try {
    const shopDomain = resolveShopDomain(req);
    const shop = getShopFullStmt.get(shopDomain);
    const apiToken = shop?.judgemApiToken || devFallbackToken(req, shopDomain);

    if (!apiToken) {
      return res
        .status(503)
        .json({ error: "Shop not configured. Please complete onboarding." });
    }

    isSyncing = true;
    try {
      const synced = await syncReviews(shopDomain, apiToken);
      res.json({ synced });
    } finally {
      isSyncing = false;
    }
  } catch (err) {
    console.error("Sync error:", err.message);
    res.status(500).json({ error: "Sync failed", detail: err.message });
  }
});

// ---------------------------------------------------------------------------
// GDPR webhooks — mandatory for Shopify App Store approval.
// All three are HMAC-signed with the app's client secret (verification
// skipped only when SHOPIFY_CLIENT_SECRET is unset, i.e. local dev).
// ---------------------------------------------------------------------------
function verifyWebhookHMAC(req, res, next) {
  const hmacHeader = req.headers["x-shopify-hmac-sha256"];
  const secret = process.env.SHOPIFY_CLIENT_SECRET;

  if (!secret) {
    console.warn("[webhook] SHOPIFY_CLIENT_SECRET not set — skipping HMAC verification (dev mode)");
    return next();
  }

  if (!hmacHeader) {
    return res.status(401).json({ error: "Missing HMAC header" });
  }

  const digest = crypto
    .createHmac("sha256", secret)
    .update(req.rawBody || Buffer.alloc(0))
    .digest("base64");

  if (digest !== hmacHeader) {
    console.warn("[webhook] Invalid HMAC signature");
    return res.status(401).json({ error: "Invalid HMAC signature" });
  }

  next();
}

// Customer requests to see what data we have about them. We store only
// reviews synced from Judge.me (attributed by reviewerName) plus shop
// config — no personal data submitted directly by end customers.
function handleCustomersDataRequest(req, res) {
  console.log("[webhook] customers/data_request received:", {
    shopDomain: req.body?.shop_domain,
    customerId: req.body?.customer?.id,
  });
  res.status(200).json({ message: "Acknowledged" });
}

// Customer requests deletion of their data. Reviews are sourced from
// Judge.me — if deleted there, they drop out on the next sync.
function handleCustomersRedact(req, res) {
  console.log("[webhook] customers/redact received:", {
    shopDomain: req.body?.shop_domain,
    customerId: req.body?.customer?.id,
  });
  res.status(200).json({ message: "Acknowledged" });
}

// Fired 48h after a shop uninstalls — delete all data for that shop.
function handleShopRedact(req, res) {
  const shopDomain = req.body?.shop_domain || req.body?.myshopify_domain;
  console.log("[webhook] shop/redact received for:", shopDomain);

  if (shopDomain) {
    try {
      const deletedReviews = db.prepare("DELETE FROM Review WHERE shopDomain = ?").run(shopDomain);
      db.prepare("DELETE FROM Shop WHERE shopDomain = ?").run(shopDomain);
      console.log(`[webhook] shop/redact: deleted ${deletedReviews.changes} reviews and shop record for ${shopDomain}`);
    } catch (err) {
      console.error("[webhook] shop/redact error:", err.message);
      // Still return 200 — Shopify does not retry on 200
    }
  }

  res.status(200).json({ message: "Acknowledged" });
}

// Shopify's compliance_topics config posts all three GDPR topics to this
// single URI, distinguished by the X-Shopify-Topic header.
const GDPR_WEBHOOK_HANDLERS = {
  "customers/data_request": handleCustomersDataRequest,
  "customers/redact": handleCustomersRedact,
  "shop/redact": handleShopRedact,
};

app.post("/webhooks", verifyWebhookHMAC, (req, res) => {
  const topic = req.headers["x-shopify-topic"];
  const handler = GDPR_WEBHOOK_HANDLERS[topic];

  if (!handler) {
    console.warn(`[webhook] Unknown or missing X-Shopify-Topic: ${topic}`);
    return res.status(404).json({ error: "Unknown webhook topic" });
  }

  handler(req, res);
});

// Individual routes kept for local testing (curl/Postman without needing
// to set X-Shopify-Topic).
app.post("/webhooks/customers/data_request", verifyWebhookHMAC, handleCustomersDataRequest);
app.post("/webhooks/customers/redact", verifyWebhookHMAC, handleCustomersRedact);
app.post("/webhooks/shop/redact", verifyWebhookHMAC, handleShopRedact);

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Reviews API running at http://localhost:${PORT}`);
  console.log(`Endpoints:`);
  console.log(`  GET  http://localhost:${PORT}/api/reviews  — serve from cache`);
  console.log(`  POST http://localhost:${PORT}/api/sync     — sync from Judge.me`);
});

// ---------------------------------------------------------------------------
// Auto-sync — runs on startup, then on the shop's configured interval
// (minutes, default 60). POST /api/admin/sync-interval reschedules this.
// ---------------------------------------------------------------------------
let autoSyncTimer = null;

function scheduleAutoSync(intervalMinutes) {
  if (autoSyncTimer) clearInterval(autoSyncTimer);
  autoSyncTimer = setInterval(runAutoSync, intervalMinutes * 60 * 1000);
}

async function runAutoSync() {
  const shopDomain = process.env.JUDGEME_SHOP_DOMAIN;
  const apiToken = process.env.JUDGEME_API_TOKEN;

  if (!shopDomain || !apiToken) {
    console.log("[auto-sync] skipped — no JUDGEME_SHOP_DOMAIN/JUDGEME_API_TOKEN in .env");
    return;
  }

  const startedAt = new Date().toISOString();
  console.log(`[auto-sync] starting at ${startedAt}`);
  isSyncing = true;
  try {
    const synced = await syncReviews(shopDomain, apiToken);
    console.log(`[auto-sync] finished at ${new Date().toISOString()} — ${synced} reviews synced`);
  } catch (err) {
    console.error(`[auto-sync] failed at ${new Date().toISOString()} — ${err.message}`);
  } finally {
    isSyncing = false;
  }
}

runAutoSync();
const initialShop = getShopFullStmt.get(process.env.JUDGEME_SHOP_DOMAIN);
scheduleAutoSync(initialShop?.syncInterval ?? 60);
