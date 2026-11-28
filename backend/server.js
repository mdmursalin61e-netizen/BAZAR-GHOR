require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const { sql, testConnection } = require("./db");
const createSupplierProductsRouter = require("./supplier-products");
const createSupplierAuth = require("./supplier-auth");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_COOKIE = "elite_admin_token";
const COOKIE_MAX_AGE = 8 * 60 * 60;
const CUSTOMER_TOKEN_TTL = "7d";

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error("JWT_SECRET is missing or too short.");
}

// Used so login takes the same time even if the account does not exist
const DUMMY_PASSWORD_HASH = bcrypt.hashSync("dummy-password-for-timing", 10);
const BCRYPT_ROUNDS = 10;

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// =====================================
// STATUS DEFINITIONS & LIMITS (FORM RULES)
// =====================================

const MAX_PRODUCT_IMAGES = 4;
const MAX_PRODUCT_LINKS = 25;

const ORDER_STATUSES = [
    "pending",
    "approved",
    "confirmed",
    "processing",
    "shipped",
    "out_for_delivery",
    "delivered",
    "rejected",
    "cancelled"
];

const PAYMENT_STATUSES = ["unpaid", "pending_verification", "paid", "rejected", "refunded"];

const DELIVERY_STATUSES = [
    "pending",
    "order_confirmed",
    "approved",
    "processing",
    "ready_for_dispatch",
    "ready_for_delivery",
    "shipped",
    "out_for_delivery",
    "delivered",
    "delivery_failed",
    "returned"
];

// Supplier can update preparation & dispatch progress; Admin controls final delivery/exceptions
const SUPPLIER_DELIVERY_ALLOWED = [
    "processing",
    "ready_for_dispatch",
    "ready_for_delivery",
    "shipped",
    "out_for_delivery",
    "delivered"
];

const ONLINE_METHODS = ["bkash", "nagad"];
const LEGACY_PAYMENT_MAP = { pending: "pending_verification", failed: "rejected" };

// =====================================
// SMALL HELPERS
// =====================================

function isValidId(value) {
    return typeof value === "string" && /^\d+$/.test(value) && Number(value) > 0;
}

function bad(res, message, status = 400) {
    return res.status(status).json({ success: false, message });
}

function str(value) {
    return typeof value === "string" ? value.trim() : "";
}

// 01XXXXXXXXX style; handles +880 / 880 prefixes, spaces and hyphens
function normalizePhone(value) {
    let p = str(value).replace(/[\s\-()]/g, "");
    if (p.startsWith("+880")) p = "0" + p.slice(4);
    else if (p.startsWith("880") && p.length >= 12) p = "0" + p.slice(3);
    return p;
}

function isValidPhone(p) {
    return /^\+?\d{7,15}$/.test(p);
}

function isSafeHttpUrl(rawUrl) {
    const clean = str(rawUrl);
    if (!clean) return false;
    if (clean.startsWith("/")) return true;
    try {
        const parsed = new URL(clean);
        return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch {
        return false;
    }
}

function normalizeImageGallery(imageUrlsInput, fallbackImageUrl = "") {
    let list = [];
    if (Array.isArray(imageUrlsInput)) {
        list = imageUrlsInput;
    } else if (typeof imageUrlsInput === "string" && imageUrlsInput.trim() !== "") {
        try {
            const parsed = JSON.parse(imageUrlsInput);
            if (Array.isArray(parsed)) list = parsed;
            else list = [imageUrlsInput];
        } catch {
            list = imageUrlsInput.split(",").map(s => s.trim());
        }
    }

    const cleaned = [];
    for (const item of list) {
        const u = str(item);
        if (u && isSafeHttpUrl(u) && !cleaned.includes(u)) {
            cleaned.push(u);
        }
    }

    const fb = str(fallbackImageUrl);
    if (cleaned.length === 0 && fb && isSafeHttpUrl(fb)) {
        cleaned.push(fb);
    }

    return cleaned;
}

function normalizeLinksInput(linksInput) {
    if (!Array.isArray(linksInput)) return [];
    const normalized = [];
    for (const item of linksInput) {
        if (!item || typeof item !== "object") continue;
        const title = str(item.title || item.name || item.label || "Link");
        const url = str(item.url || item.link || "");
        if (!url || !isSafeHttpUrl(url)) continue;
        const visibility = str(item.visibility || (item.is_public === false ? "private" : "public")).toLowerCase() === "private"
            ? "private"
            : "public";
        const platform = str(item.platform || detectPlatformFromUrl(url));
        normalized.push({
            title: title.slice(0, 120),
            url: url.slice(0, 1000),
            platform: platform.slice(0, 50),
            visibility,
            is_public: visibility === "public"
        });
    }
    return normalized;
}

function detectPlatformFromUrl(url) {
    const lower = str(url).toLowerCase();
    if (lower.includes("youtube.com") || lower.includes("youtu.be")) return "youtube";
    if (lower.includes("facebook.com") || lower.includes("fb.watch")) return "facebook";
    if (lower.includes("instagram.com")) return "instagram";
    if (lower.includes("tiktok.com")) return "tiktok";
    return "website";
}

async function recordOrderEvent(orderId, eventType, oldValue, newValue, note = "", actor = "system", extra = {}) {
    try {
        await sql`
            INSERT INTO order_events (
                order_id, event_type, old_value, new_value, note, actor,
                delivery_location, tracking_number, courier_name, gps_lat, gps_lng
            )
            VALUES (
                ${orderId},
                ${eventType},
                ${oldValue ?? null},
                ${newValue ?? null},
                ${note || null},
                ${actor || "system"},
                ${extra.delivery_location ?? null},
                ${extra.tracking_number ?? null},
                ${extra.courier_name ?? null},
                ${extra.gps_lat ?? null},
                ${extra.gps_lng ?? null}
            )
        `;
    } catch (error) {
        console.error("Failed to record order event:", error.message);
    }
}

// =====================================
// PUBLIC DATA CACHE
// =====================================

const PUBLIC_CACHE_TTL = 15 * 1000;
const publicDataCache = new Map();

function getPublicCache(key) {
    const cached = publicDataCache.get(key);
    if (!cached) return null;
    if (Date.now() >= cached.expiresAt) {
        publicDataCache.delete(key);
        return null;
    }
    return cached.data;
}

function setPublicCache(key, data) {
    publicDataCache.set(key, { data, expiresAt: Date.now() + PUBLIC_CACHE_TTL });
}

function clearPublicCache(key) {
    if (key) {
        publicDataCache.delete(key);
    } else {
        publicDataCache.clear();
    }
}

function setPublicCacheHeaders(res) {
    res.setHeader("Cache-Control", "public, max-age=15, stale-while-revalidate=30");
}

// =====================================
// SECURITY CONFIGURATION
// =====================================

app.disable("x-powered-by");

if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "250kb" }));
app.use(express.urlencoded({ extended: true, limit: "250kb", parameterLimit: 200 }));

app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    next();
});

// =====================================
// IMAGE UPLOAD CONFIGURATION
// =====================================

const uploadDirectory = path.join(__dirname, "..", "uploads");

if (!fs.existsSync(uploadDirectory)) {
    fs.mkdirSync(uploadDirectory, { recursive: true });
}

const allowedImageTypes = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/gif": "gif"
};

const imageUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024, files: MAX_PRODUCT_IMAGES },
    fileFilter: (req, file, callback) => {
        if (!Object.keys(allowedImageTypes).includes(file.mimetype)) {
            return callback(new Error("Only JPG, PNG, WEBP and GIF images are allowed."));
        }
        callback(null, true);
    }
});

// =====================================
// RATE LIMITERS
// =====================================

function makeLimiter(windowMs, limit, message, extra = {}) {
    return rateLimit({
        windowMs,
        limit,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: { success: false, message },
        ...extra
    });
}

const adminLoginLimiter = makeLimiter(15 * 60 * 1000, 5,
    "Too many login attempts. Please try again after 15 minutes.", { skipSuccessfulRequests: true });
const customerLoginLimiter = makeLimiter(15 * 60 * 1000, 10,
    "Too many login attempts. Please try again after 15 minutes.", { skipSuccessfulRequests: true });
const registrationLimiter = makeLimiter(60 * 60 * 1000, 10,
    "Too many registration attempts. Please try again later.");
const contactLimiter = makeLimiter(15 * 60 * 1000, 10,
    "Too many messages submitted. Please try again later.");
const orderLimiter = makeLimiter(15 * 60 * 1000, 10,
    "Too many order attempts. Please try again later.");
const imageUploadLimiter = makeLimiter(15 * 60 * 1000, 30,
    "Too many image uploads. Please try again later.");

// =====================================
// ADMIN COOKIE HELPERS
// =====================================

function getAdminToken(req) {
    const cookies = (req.headers.cookie || "").split(";");
    const adminCookie = cookies.find(c => c.trim().startsWith(`${TOKEN_COOKIE}=`));
    if (!adminCookie) return null;
    try {
        return decodeURIComponent(adminCookie.trim().substring(TOKEN_COOKIE.length + 1));
    } catch {
        return null;
    }
}

function setAdminCookie(res, token) {
    let cookie = `${TOKEN_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${COOKIE_MAX_AGE}`;
    if (process.env.NODE_ENV === "production") cookie += "; Secure";
    res.setHeader("Set-Cookie", cookie);
}

function clearAdminCookie(res) {
    let cookie = `${TOKEN_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;
    if (process.env.NODE_ENV === "production") cookie += "; Secure";
    res.setHeader("Set-Cookie", cookie);
}

// =====================================
// ADMIN AUTHENTICATION
// =====================================

async function requireAdmin(req, res, next) {
    const token = getAdminToken(req);

    if (!token) return bad(res, "Please login first.", 401);

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    } catch (error) {
        clearAdminCookie(res);
        return bad(res, "Session expired. Please login again.", 401);
    }

    if (!decoded.sub || decoded.type !== "admin") {
        clearAdminCookie(res);
        return bad(res, "Invalid session.", 401);
    }

    try {
        const admins = await sql`
            SELECT id, name, email, role, is_active
            FROM admins
            WHERE id = ${decoded.sub}
            LIMIT 1
        `;

        if (admins.length === 0 || !admins[0].is_active) {
            clearAdminCookie(res);
            return bad(res, "Admin account is inactive.", 401);
        }

        req.admin = admins[0];
        return next();
    } catch (error) {
        console.error("Admin authentication database error:", error);
        return bad(res, "Authentication service is temporarily unavailable.", 503);
    }
}

// =====================================
// CUSTOMER AUTHENTICATION (Bearer token)
// =====================================

function signCustomerToken(customer) {
    return jwt.sign(
        { type: "customer", tv: Number(customer.token_version) || 0 },
        JWT_SECRET,
        { subject: String(customer.id), expiresIn: CUSTOMER_TOKEN_TTL, algorithm: "HS256" }
    );
}

function publicCustomer(c) {
    return {
        id: c.id,
        name: c.name,
        email: c.email,
        phone: c.phone,
        address: c.address || "",
        created_at: c.created_at
    };
}

async function loadCustomerFromRequest(req) {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) return null;

    let decoded;
    try {
        decoded = jwt.verify(header.slice(7), JWT_SECRET, { algorithms: ["HS256"] });
    } catch {
        return null;
    }

    if (!decoded.sub || decoded.type !== "customer") return null;

    const rows = await sql`
        SELECT id, name, email, phone, address, created_at, token_version, is_archived
        FROM customers
        WHERE id = ${decoded.sub}
          AND password_hash IS NOT NULL
        LIMIT 1
    `;

    if (!rows.length || rows[0].is_archived) return null;
    if (Number(rows[0].token_version) !== Number(decoded.tv)) return null;

    return rows[0];
}

async function requireCustomer(req, res, next) {
    try {
        const customer = await loadCustomerFromRequest(req);
        if (!customer) return bad(res, "Please login first.", 401);
        req.customer = customer;
        return next();
    } catch (error) {
        console.error("Customer authentication error:", error);
        return bad(res, "Authentication service is temporarily unavailable.", 503);
    }
}

async function optionalCustomer(req, res, next) {
    try {
        req.customer = await loadCustomerFromRequest(req);
    } catch (error) {
        console.error("Optional customer auth error:", error);
        req.customer = null;
    }
    next();
}

// =====================================
// SUPPLIER AUTHENTICATION + PRODUCT ROUTER
// =====================================

const supplierAuth = createSupplierAuth({ sql, requireAdmin, jwtSecret: JWT_SECRET });
app.use("/api", supplierAuth.router);

app.use(
    "/api/admin",
    createSupplierProductsRouter({
        sql,
        requireAdmin,
        requireSupplier: supplierAuth.requireSupplier,
        clearPublicCache
    })
);

// =====================================
// STATIC ASSETS, PAGES AND UPLOADED IMAGES
// =====================================

app.use("/assets", express.static(path.join(__dirname, "..", "assets"), {
    maxAge: "1d",
    etag: true,
    lastModified: true
}));

// Public HTML pages
app.use("/pages", express.static(path.join(__dirname, "..", "pages"), {
    index: false,
    etag: true,
    lastModified: true
}));

app.use("/uploads", express.static(uploadDirectory, {
    dotfiles: "deny",
    index: false,
    maxAge: "7d",
    etag: true,
    lastModified: true
}));

app.get("/", (req, res) => {
    res.setHeader("Cache-Control", "no-cache");
    res.sendFile(path.join(__dirname, "..", "index.html"));
});


// =====================================
// HEALTH CHECK
// =====================================

app.get("/api/health", (req, res) => {
    res.json({ success: true, message: "Backend is running." });
});

app.get("/api/health/db", async (req, res) => {
    try {
        const time = await testConnection();
        res.json({ success: true, message: "Database connected.", database_time: time });
    } catch (error) {
        console.error("DB health check error:", error);
        bad(res, "Database connection failed.", 503);
    }
});

// =====================================
// DATABASE MIGRATIONS (safe to run on every start; old data is kept)
// =====================================

async function step(label, fn) {
    try {
        await fn();
    } catch (error) {
        console.error(`Migration step failed [${label}]:`, error.message);
    }
}

async function runOnce(name, fn) {
    try {
        const done = await sql`SELECT 1 FROM schema_migrations WHERE name = ${name} LIMIT 1`;
        if (done.length) return;
        await fn();
        await sql`INSERT INTO schema_migrations (name) VALUES (${name}) ON CONFLICT DO NOTHING`;
    } catch (error) {
        console.error(`One-time migration failed [${name}]:`, error.message);
    }
}

async function runMigrations() {
    await step("schema_migrations", () => sql`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);

    // ---- customers: password login ----
    await step("customers.password_hash", () => sql`ALTER TABLE customers ADD COLUMN IF NOT EXISTS password_hash TEXT`);
    await step("customers.token_version", () => sql`ALTER TABLE customers ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0`);
    await step("customers.address", () => sql`ALTER TABLE customers ADD COLUMN IF NOT EXISTS address TEXT`);
    await step("customers.last_login_at", () => sql`ALTER TABLE customers ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ`);
    await step("idx customers email", () => sql`CREATE INDEX IF NOT EXISTS idx_customers_email_lower ON customers (LOWER(email))`);
    await step("idx customers phone", () => sql`CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers (phone)`);

    // ---- orders: approval + delivery + GPS/courier + payment verification ----
    await step("orders.approval_status", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'pending'`);
    await step("orders.approval_note", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS approval_note TEXT`);
    await step("orders.approved_at", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ`);
    await step("orders.approved_by", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS approved_by TEXT`);
    await step("orders.delivery_status", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_status TEXT NOT NULL DEFAULT 'pending'`);
    await step("orders.delivery_charge", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_charge NUMERIC(12,2) NOT NULL DEFAULT 0`);
    await step("orders.delivery_location", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_location TEXT`);
    await step("orders.delivery_note", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_note TEXT`);
    await step("orders.tracking_number", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS tracking_number TEXT`);
    await step("orders.tracking_info", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS tracking_info TEXT`);
    await step("orders.courier_name", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS courier_name TEXT`);
    await step("orders.courier_api_ref", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS courier_api_ref TEXT`);
    await step("orders.gps_lat", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS gps_lat DOUBLE PRECISION`);
    await step("orders.gps_lng", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS gps_lng DOUBLE PRECISION`);
    await step("orders.gps_updated_at", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS gps_updated_at TIMESTAMPTZ`);
    await step("orders.delivered_at", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ`);
    await step("orders.delivery_updated_at", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_updated_at TIMESTAMPTZ`);
    await step("orders.delivery_name", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_name TEXT`);
    await step("orders.delivery_phone", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_phone TEXT`);
    await step("orders.supplier_id", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS supplier_id BIGINT`);
    await step("orders.supplier_progress", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS supplier_progress TEXT`);
    await step("orders.supplier_note", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS supplier_note TEXT`);
    await step("orders.supplier_updated_at", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS supplier_updated_at TIMESTAMPTZ`);
    await step("orders.payment_verified_at", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_verified_at TIMESTAMPTZ`);
    await step("orders.payment_verified_by", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_verified_by TEXT`);
    await step("orders.payment_note", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_note TEXT`);
    await step("idx orders customer", () => sql`CREATE INDEX IF NOT EXISTS idx_orders_customer_id ON orders (customer_id)`);
    await step("idx orders tracking", () => sql`CREATE INDEX IF NOT EXISTS idx_orders_tracking_number ON orders (tracking_number)`);
    await step("idx order_items order", () => sql`CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items (order_id)`);

    // ---- products: category + multiple image gallery (max 4) + links (max 25) ----
    await step("products.category", () => sql`ALTER TABLE products ADD COLUMN IF NOT EXISTS category TEXT`);
    await step("products.supplier_id", () => sql`ALTER TABLE products ADD COLUMN IF NOT EXISTS supplier_id BIGINT`);

    await step("products.image_urls", async () => {
        await sql`
            ALTER TABLE products
            ADD COLUMN IF NOT EXISTS image_urls JSONB
            NOT NULL DEFAULT '[]'::jsonb
        `;

        await sql`
            UPDATE products
            SET image_urls = jsonb_build_array(image_url)
            WHERE COALESCE(TRIM(image_url), '') <> ''
              AND (
                  image_urls IS NULL
                  OR image_urls = '[]'::jsonb
              )
        `;
    });

    await step("product_links table", () => sql`
        CREATE TABLE IF NOT EXISTS product_links (
            id BIGSERIAL PRIMARY KEY,
            product_id BIGINT NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            platform TEXT NOT NULL DEFAULT 'website',
            visibility TEXT NOT NULL DEFAULT 'public',
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_by_role TEXT NOT NULL DEFAULT 'admin',
            created_by_id BIGINT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
    await step("idx product_links product_id", () => sql`CREATE INDEX IF NOT EXISTS idx_product_links_product_id ON product_links (product_id)`);

    await step("categories table", () => sql`
        CREATE TABLE IF NOT EXISTS categories (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
    await step("idx categories name", () => sql`CREATE UNIQUE INDEX IF NOT EXISTS idx_categories_name_lower ON categories (LOWER(name))`);

    // ---- messages: customer link + admin reply ----
    await step("messages.customer_id", () => sql`ALTER TABLE messages ADD COLUMN IF NOT EXISTS customer_id BIGINT`);
    await step("messages.order_id", () => sql`ALTER TABLE messages ADD COLUMN IF NOT EXISTS order_id BIGINT`);
    await step("messages.admin_reply", () => sql`ALTER TABLE messages ADD COLUMN IF NOT EXISTS admin_reply TEXT`);
    await step("messages.replied_at", () => sql`ALTER TABLE messages ADD COLUMN IF NOT EXISTS replied_at TIMESTAMPTZ`);
    await step("idx messages customer", () => sql`CREATE INDEX IF NOT EXISTS idx_messages_customer_id ON messages (customer_id)`);

    // ---- settings, order events (timeline + GPS/courier), supplier messages ----
    await step("app_settings", () => sql`
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT '',
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);

    await step("order_events", () => sql`
        CREATE TABLE IF NOT EXISTS order_events (
            id BIGSERIAL PRIMARY KEY,
            order_id BIGINT NOT NULL,
            event_type TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            note TEXT,
            actor TEXT,
            delivery_location TEXT,
            tracking_number TEXT,
            courier_name TEXT,
            gps_lat DOUBLE PRECISION,
            gps_lng DOUBLE PRECISION,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
    await step("order_events extra cols", async () => {
        await sql`ALTER TABLE order_events ADD COLUMN IF NOT EXISTS delivery_location TEXT`;
        await sql`ALTER TABLE order_events ADD COLUMN IF NOT EXISTS tracking_number TEXT`;
        await sql`ALTER TABLE order_events ADD COLUMN IF NOT EXISTS courier_name TEXT`;
        await sql`ALTER TABLE order_events ADD COLUMN IF NOT EXISTS gps_lat DOUBLE PRECISION`;
        await sql`ALTER TABLE order_events ADD COLUMN IF NOT EXISTS gps_lng DOUBLE PRECISION`;
    });
    await step("idx order_events", () => sql`CREATE INDEX IF NOT EXISTS idx_order_events_order_id ON order_events (order_id)`);

    await step("supplier_messages", () => sql`
        CREATE TABLE IF NOT EXISTS supplier_messages (
            id BIGSERIAL PRIMARY KEY,
            supplier_id BIGINT NOT NULL,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
    await step("idx supplier_messages", () => sql`CREATE INDEX IF NOT EXISTS idx_supplier_messages_supplier ON supplier_messages (supplier_id)`);

    // ---- one-time: relax old CHECK constraints so the new status values can be saved ----
    await runOnce("relax_order_status_constraints_v1", () => sql`
        DO $$
        DECLARE r RECORD;
        BEGIN
            FOR r IN
                SELECT conname FROM pg_constraint
                WHERE conrelid = 'orders'::regclass
                  AND contype = 'c'
                  AND pg_get_constraintdef(oid) ILIKE '%status%'
            LOOP
                EXECUTE format('ALTER TABLE orders DROP CONSTRAINT %I', r.conname);
            END LOOP;
        END $$;
    `);

    // ---- one-time: convert old order data to the new status model ----
    await runOnce("backfill_order_statuses_v1", async () => {
        await sql`UPDATE orders SET payment_status = 'rejected' WHERE payment_status = 'failed'`;
        await sql`UPDATE orders SET payment_status = 'pending_verification'
                  WHERE payment_status IN ('pending', 'unpaid')
                    AND payment_method IN ('bkash', 'nagad')
                    AND COALESCE(payment_reference, '') <> ''`;
        await sql`UPDATE orders SET payment_status = 'unpaid'
                  WHERE payment_status = 'pending' AND payment_method = 'cod'`;
        await sql`UPDATE orders SET delivery_status = CASE status
                      WHEN 'confirmed' THEN 'order_confirmed'
                      WHEN 'processing' THEN 'processing'
                      WHEN 'shipped' THEN 'shipped'
                      WHEN 'delivered' THEN 'delivered'
                      ELSE delivery_status END
                  WHERE status IN ('confirmed', 'processing', 'shipped', 'delivered')`;
        await sql`UPDATE orders SET approval_status = CASE
                      WHEN status = 'rejected' THEN 'rejected'
                      WHEN status IN ('confirmed', 'approved', 'processing', 'shipped', 'out_for_delivery', 'delivered') THEN 'approved'
                      ELSE 'pending' END
                  WHERE COALESCE(approval_status, '') = ''`;
        await sql`UPDATE orders SET delivered_at = COALESCE(delivered_at, created_at) WHERE status = 'delivered'`;
    });

    // ---- default settings (only inserted if missing) ----
    await step("seed settings", () => {
        const defaults = {
            delivery_charge: String(Number(process.env.DEFAULT_DELIVERY_CHARGE) || 0),
            bkash_number: process.env.BKASH_MERCHANT_NUMBER || "01740470179",
            nagad_number: process.env.NAGAD_MERCHANT_NUMBER || "01307359149",
            whatsapp_number: process.env.WHATSAPP_NUMBER || "8801933018061",
            facebook_url: process.env.FACEBOOK_URL || "",
            courier_api_enabled: "false",
            courier_provider: "custom",
            courier_api_url: ""
        };
        return sql`
            INSERT INTO app_settings (key, value)
            SELECT key, value FROM jsonb_each_text(${JSON.stringify(defaults)}::jsonb)
            ON CONFLICT (key) DO NOTHING
        `;
    });

    // ---- categories from products that already have a category ----
    await step("seed categories", () => sql`
        INSERT INTO categories (name)
        SELECT DISTINCT TRIM(category) FROM products
        WHERE COALESCE(TRIM(category), '') <> ''
        ON CONFLICT DO NOTHING
    `);

    console.log("Database migrations finished.");
}

// =====================================
// SETTINGS HELPERS
// =====================================

const SETTING_KEYS = [
    "delivery_charge",
    "bkash_number",
    "nagad_number",
    "whatsapp_number",
    "facebook_url",
    "courier_api_enabled",
    "courier_provider",
    "courier_api_url"
];

async function getSettings(fresh = false) {
    if (!fresh) {
        const cached = getPublicCache("settings");
        if (cached) return cached;
    }

    const rows = await sql`SELECT key, value FROM app_settings`;
    const settings = {
        delivery_charge: 0,
        bkash_number: "",
        nagad_number: "",
        whatsapp_number: "",
        facebook_url: "",
        courier_api_enabled: "false",
        courier_provider: "custom",
        courier_api_url: ""
    };

    for (const row of rows) {
        if (SETTING_KEYS.includes(row.key)) settings[row.key] = row.value;
    }

    settings.delivery_charge = Number(settings.delivery_charge) || 0;
    setPublicCache("settings", settings);
    return settings;
}

app.get("/api/settings/public", async (req, res) => {
    try {
        const settings = await getSettings();

        setPublicCacheHeaders(res);

        res.json({
            success: true,
            settings: {
                delivery_charge: settings.delivery_charge,
                nagad_number: settings.nagad_number,
                bkash_number: settings.bkash_number,
                whatsapp_number: settings.whatsapp_number,
                facebook_url: settings.facebook_url
            }
        });
    } catch (error) {
        console.error("Public settings error:", error);
        bad(res, "Could not load settings.", 500);
    }
});

// =====================================
// PUBLIC CATEGORIES / PRODUCTS / DETAILS / LINKS / SERVICES
// =====================================

app.get("/api/categories", async (req, res) => {
    try {
        let categories = getPublicCache("categories");
        if (!categories) {
            categories = await sql`
                SELECT id, name FROM categories
                WHERE is_active = TRUE
                ORDER BY name ASC
            `;
            setPublicCache("categories", categories);
        }
        setPublicCacheHeaders(res);
        res.json({ success: true, categories });
    } catch (error) {
        console.error("Public categories error:", error);
        bad(res, "Could not load categories.", 500);
    }
});

app.get("/api/products", async (req, res) => {
    try {
        let products = getPublicCache("products");

        if (!products) {
            products = await sql`
                SELECT
                    p.id,
                    p.name,
                    p.description,
                    CASE
                        WHEN p.discount_enabled = TRUE AND p.discount_percent > 0
                        THEN ROUND(p.price * (1 - p.discount_percent / 100.0), 2)
                        ELSE p.price
                    END AS price,
                    p.price AS old_price,
                    CASE WHEN p.discount_enabled = TRUE THEN p.discount_percent ELSE 0 END AS discount_percent,
                    p.discount_enabled,
                    p.stock_quantity,
                    p.image_url,
                    p.image_urls,
                    p.category
                FROM products p
                WHERE p.is_active = TRUE
                ORDER BY p.id DESC
            `;

            const links = await sql`
                SELECT id, product_id, title, url, platform, sort_order
                FROM product_links
                WHERE visibility = 'public'
                ORDER BY sort_order ASC, id ASC
            `;

            const linksByProduct = new Map();
            for (const l of links) {
                if (!linksByProduct.has(String(l.product_id))) {
                    linksByProduct.set(String(l.product_id), []);
                }
                linksByProduct.get(String(l.product_id)).push(l);
            }

            products = products.map(p => {
                const gallery = normalizeImageGallery(p.image_urls, p.image_url).slice(0, MAX_PRODUCT_IMAGES);
                return {
                    ...p,
                    image_url: gallery[0] || p.image_url || "",
                    image_urls: gallery,
                    links: linksByProduct.get(String(p.id)) || []
                };
            });

            setPublicCache("products", products);
        }

        setPublicCacheHeaders(res);
        return res.json({ success: true, products });
    } catch (error) {
        console.error("Public products error:", error);
        return bad(res, "Could not load products.", 500);
    }
});

// Product Details Page API (Gallery up to 4 images + Description + Public Links only)
app.get("/api/products/:id", async (req, res) => {
    try {
        if (!isValidId(req.params.id)) return bad(res, "Invalid product ID.");

        const rows = await sql`
            SELECT
                p.id,
                p.name,
                p.description,
                CASE
                    WHEN p.discount_enabled = TRUE AND p.discount_percent > 0
                    THEN ROUND(p.price * (1 - p.discount_percent / 100.0), 2)
                    ELSE p.price
                END AS price,
                p.price AS old_price,
                CASE WHEN p.discount_enabled = TRUE THEN p.discount_percent ELSE 0 END AS discount_percent,
                p.discount_enabled,
                p.stock_quantity,
                p.image_url,
                p.image_urls,
                p.category
            FROM products p
            WHERE p.id = ${req.params.id} AND p.is_active = TRUE
            LIMIT 1
        `;

        if (!rows.length) return bad(res, "Product not found.", 404);

        const p = rows[0];
        const gallery = normalizeImageGallery(p.image_urls, p.image_url).slice(0, MAX_PRODUCT_IMAGES);
        const publicLinks = await sql`
            SELECT id, product_id, title, url, platform, sort_order
            FROM product_links
            WHERE product_id = ${p.id} AND visibility = 'public'
            ORDER BY sort_order ASC, id ASC
        `;

        return res.json({
            success: true,
            product: {
                ...p,
                image_url: gallery[0] || p.image_url || "",
                image_urls: gallery,
                links: publicLinks
            }
        });
    } catch (error) {
        console.error("Product details error:", error);
        return bad(res, "Could not load product details.", 500);
    }
});

app.get("/api/products/:id/links", async (req, res) => {
    try {
        if (!isValidId(req.params.id)) return bad(res, "Invalid product ID.");
        const links = await sql`
            SELECT id, product_id, title, url, platform, sort_order
            FROM product_links
            WHERE product_id = ${req.params.id} AND visibility = 'public'
            ORDER BY sort_order ASC, id ASC
        `;
        return res.json({ success: true, links });
    } catch (error) {
        console.error("Public product links error:", error);
        return bad(res, "Could not load product links.", 500);
    }
});

app.get("/api/services", async (req, res) => {
    try {
        let services = getPublicCache("services");

        if (!services) {
            services = await sql`
                SELECT id, title, slug, description
                FROM services
                WHERE is_active = TRUE
                ORDER BY id DESC
            `;
            setPublicCache("services", services);
        }

        setPublicCacheHeaders(res);
        return res.json({ success: true, services });
    } catch (error) {
        console.error("Public services error:", error);
        return bad(res, "Could not load services.", 500);
    }
});

// =====================================
// CUSTOMER REGISTRATION / LOGIN / PROFILE
// =====================================

async function handleCustomerRegister(req, res) {
    try {
        const { name, email, phone, password } = req.body || {};

        const cleanName = str(name);
        const cleanEmail = str(email).toLowerCase();
        const cleanPhone = normalizePhone(phone);

        if (!cleanName || cleanName.length > 150) return bad(res, "Please enter a valid name.");
        if (!cleanEmail || cleanEmail.length > 255 || !EMAIL_REGEX.test(cleanEmail)) {
            return bad(res, "Please enter a valid email address.");
        }
        if (!isValidPhone(cleanPhone)) return bad(res, "Please enter a valid phone number.");
        if (typeof password !== "string" || password.length < 6 || password.length > 128) {
            return bad(res, "Password must be between 6 and 128 characters.");
        }

        const phoneTaken = await sql`
            SELECT id FROM customers
            WHERE phone = ${cleanPhone} AND password_hash IS NOT NULL
            LIMIT 1
        `;

        const existing = await sql`
            SELECT id, phone, password_hash, is_archived
            FROM customers
            WHERE LOWER(email) = ${cleanEmail}
            LIMIT 1
        `;

        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        let customer;

        if (existing.length > 0) {
            const old = existing[0];

            const canClaim =
                !old.password_hash &&
                !old.is_archived &&
                normalizePhone(old.phone) === cleanPhone;

            if (!canClaim) return bad(res, "This email is already registered.", 409);
            if (phoneTaken.length > 0 && String(phoneTaken[0].id) !== String(old.id)) {
                return bad(res, "This phone number is already registered.", 409);
            }

            const updated = await sql`
                UPDATE customers
                SET name = ${cleanName},
                    phone = ${cleanPhone},
                    password_hash = ${passwordHash},
                    last_login_at = NOW()
                WHERE id = ${old.id} AND password_hash IS NULL
                RETURNING id, name, email, phone, address, created_at, token_version
            `;

            if (!updated.length) return bad(res, "This email is already registered.", 409);
            customer = updated[0];
        } else {
            if (phoneTaken.length > 0) return bad(res, "This phone number is already registered.", 409);

            const inserted = await sql`
                INSERT INTO customers (name, email, phone, password_hash, last_login_at)
                VALUES (${cleanName}, ${cleanEmail}, ${cleanPhone}, ${passwordHash}, NOW())
                RETURNING id, name, email, phone, address, created_at, token_version
            `;
            customer = inserted[0];
        }

        res.setHeader("Cache-Control", "no-store");

        return res.status(201).json({
            success: true,
            message: "Registration successful.",
            token: signCustomerToken(customer),
            customer: publicCustomer(customer)
        });
    } catch (error) {
        console.error("Customer registration error:", error);
        if (error && error.code === "23505") {
            return bad(res, "An account with this email or phone already exists.", 409);
        }
        return bad(res, "Registration failed. Please try again.", 500);
    }
}

async function handleCustomerLogin(req, res) {
    try {
        const { email, phone, identifier, password } = req.body || {};
        if (typeof password !== "string" || !password) {
            return bad(res, "Please enter your email/phone and password.");
        }

        const rawId = str(identifier || email || phone);
        if (!rawId) return bad(res, "Please enter your email/phone and password.");

        const isEmail = rawId.includes("@");
        const cleanEmail = isEmail ? rawId.toLowerCase() : "";
        const cleanPhone = !isEmail ? normalizePhone(rawId) : "";

        const rows = isEmail
            ? await sql`
                SELECT id, name, email, phone, address, created_at, password_hash, token_version, is_archived
                FROM customers
                WHERE LOWER(email) = ${cleanEmail}
                LIMIT 1
              `
            : await sql`
                SELECT id, name, email, phone, address, created_at, password_hash, token_version, is_archived
                FROM customers
                WHERE phone = ${cleanPhone}
                LIMIT 1
              `;

        const candidate = rows[0] || null;
        const hashToCheck = candidate && candidate.password_hash ? candidate.password_hash : DUMMY_PASSWORD_HASH;
        const passwordMatch = await bcrypt.compare(password, hashToCheck);

        if (!candidate || !candidate.password_hash || candidate.is_archived || !passwordMatch) {
            return bad(res, "Invalid credentials.", 401);
        }

        const updated = await sql`
            UPDATE customers
            SET last_login_at = NOW()
            WHERE id = ${candidate.id}
            RETURNING id, name, email, phone, address, created_at, token_version
        `;

        const customer = updated[0] || candidate;
        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            message: "Login successful.",
            token: signCustomerToken(customer),
            customer: publicCustomer(customer)
        });
    } catch (error) {
        console.error("Customer login error:", error);
        return bad(res, "Login failed. Please try again.", 500);
    }
}

app.post("/api/customer/register", registrationLimiter, handleCustomerRegister);
app.post("/api/customers/register", registrationLimiter, handleCustomerRegister);
app.post("/api/customer/login", customerLoginLimiter, handleCustomerLogin);
app.post("/api/customers/login", customerLoginLimiter, handleCustomerLogin);

app.get("/api/customer/me", requireCustomer, (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    return res.json({ success: true, customer: publicCustomer(req.customer) });
});

app.put("/api/customer/profile", requireCustomer, async (req, res) => {
    try {
        const { name, phone, address } = req.body || {};
        const cleanName = name !== undefined ? str(name) : req.customer.name;
        const cleanPhone = phone !== undefined ? normalizePhone(phone) : req.customer.phone;
        const cleanAddress = address !== undefined ? str(address) : (req.customer.address || "");

        if (!cleanName || cleanName.length > 150) return bad(res, "Please enter a valid name.");
        if (!isValidPhone(cleanPhone)) return bad(res, "Please enter a valid phone number.");
        if (cleanAddress.length > 500) return bad(res, "Address is too long.");

        const phoneTaken = await sql`
            SELECT id FROM customers
            WHERE phone = ${cleanPhone} AND id <> ${req.customer.id} AND password_hash IS NOT NULL
            LIMIT 1
        `;
        if (phoneTaken.length > 0) return bad(res, "This phone number is already in use.", 409);

        const updated = await sql`
            UPDATE customers
            SET name = ${cleanName}, phone = ${cleanPhone}, address = ${cleanAddress}
            WHERE id = ${req.customer.id}
            RETURNING id, name, email, phone, address, created_at, token_version
        `;

        res.setHeader("Cache-Control", "no-store");
        return res.json({ success: true, message: "Profile updated.", customer: publicCustomer(updated[0]) });
    } catch (error) {
        console.error("Customer profile update error:", error);
        return bad(res, "Could not update profile.", 500);
    }
});

// =====================================
// CUSTOMER ORDERS & ORDER TRACKING TIMELINE
// =====================================

app.post("/api/orders", orderLimiter, optionalCustomer, async (req, res) => {
    try {
        const body = req.body || {};
        const items = Array.isArray(body.items) ? body.items : [];
        if (!items.length) return bad(res, "Your cart is empty.");

        const customerName = str(body.customer_name || (req.customer && req.customer.name));
        const customerPhone = normalizePhone(body.customer_phone || (req.customer && req.customer.phone));
        const customerEmail = str(body.customer_email || (req.customer && req.customer.email)).toLowerCase();
        const shippingAddress = str(body.shipping_address || body.address || (req.customer && req.customer.address));
        const paymentMethod = str(body.payment_method || "cod").toLowerCase();
        const paymentReference = str(body.payment_reference || "");
        const note = str(body.note || "");

        if (!customerName || customerName.length > 150) return bad(res, "Please enter your name.");
        if (!isValidPhone(customerPhone)) return bad(res, "Please enter a valid phone number.");
        if (customerEmail && (!EMAIL_REGEX.test(customerEmail) || customerEmail.length > 255)) {
            return bad(res, "Please enter a valid email address.");
        }
        if (!shippingAddress || shippingAddress.length > 500) {
            return bad(res, "Please enter a shipping address.");
        }

        const allowedMethods = ["cod", ...ONLINE_METHODS];
        if (!allowedMethods.includes(paymentMethod)) {
            return bad(res, "Unsupported payment method.");
        }
        if (ONLINE_METHODS.includes(paymentMethod) && !paymentReference) {
            return bad(res, `Please enter your ${paymentMethod.toUpperCase()} transaction reference.`);
        }

        let subtotal = 0;
        const resolvedItems = [];
        let primarySupplierId = null;

        for (const rawItem of items) {
            const productId = rawItem && rawItem.product_id;
            const qty = Number(rawItem && rawItem.quantity);
            if (!productId || !/^\d+$/.test(String(productId)) || !Number.isInteger(qty) || qty < 1 || qty > 100) {
                return bad(res, "Invalid item or quantity in cart.");
            }

            const prodRows = await sql`
                SELECT
                    id, name, price, discount_enabled, discount_percent, stock_quantity, is_active, supplier_id
                FROM products
                WHERE id = ${productId}
                LIMIT 1
            `;
            if (!prodRows.length || !prodRows[0].is_active) {
                return bad(res, "One of the selected products is unavailable.");
            }

            const p = prodRows[0];
            if (Number(p.stock_quantity) < qty) {
                return bad(res, `Insufficient stock for ${p.name}.`);
            }

            const unitPrice = (p.discount_enabled && Number(p.discount_percent) > 0)
                ? Number((Number(p.price) * (1 - Number(p.discount_percent) / 100)).toFixed(2))
                : Number(p.price);

            const lineTotal = Number((unitPrice * qty).toFixed(2));
            subtotal = Number((subtotal + lineTotal).toFixed(2));

            if (!primarySupplierId && p.supplier_id) {
                primarySupplierId = p.supplier_id;
            }

            resolvedItems.push({
                product_id: p.id,
                product_name: p.name,
                quantity: qty,
                unit_price: unitPrice,
                line_total: lineTotal
            });
        }

        const settings = await getSettings();
        const deliveryCharge = Number(settings.delivery_charge) || 0;
        const totalAmount = Number((subtotal + deliveryCharge).toFixed(2));

        const paymentStatus = ONLINE_METHODS.includes(paymentMethod) ? "pending_verification" : "unpaid";

        let customerId = req.customer ? req.customer.id : null;
        if (!customerId) {
            const existingCust = await sql`
                SELECT id FROM customers WHERE phone = ${customerPhone} LIMIT 1
            `;
            if (existingCust.length) {
                customerId = existingCust[0].id;
            } else {
                const createdCust = await sql`
                    INSERT INTO customers (name, email, phone, address)
                    VALUES (${customerName}, ${customerEmail || null}, ${customerPhone}, ${shippingAddress})
                    RETURNING id
                `;
                customerId = createdCust[0].id;
            }
        }

        const trackingNumber = "BG-" + crypto.randomBytes(4).toString("hex").toUpperCase();

        const createdOrder = await sql`
            INSERT INTO orders (
                customer_id, customer_name, customer_phone, customer_email, shipping_address,
                subtotal, delivery_charge, total_amount,
                payment_method, payment_reference, payment_status,
                status, approval_status, delivery_status, tracking_number, note, supplier_id
            )
            VALUES (
                ${customerId}, ${customerName}, ${customerPhone}, ${customerEmail || null}, ${shippingAddress},
                ${subtotal}, ${deliveryCharge}, ${totalAmount},
                ${paymentMethod}, ${paymentReference || null}, ${paymentStatus},
                'pending', 'pending', 'pending', ${trackingNumber}, ${note || null}, ${primarySupplierId}
            )
            RETURNING *
        `;

        const order = createdOrder[0];

        for (const item of resolvedItems) {
            await sql`
                INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, line_total)
                VALUES (${order.id}, ${item.product_id}, ${item.product_name}, ${item.quantity}, ${item.unit_price}, ${item.line_total})
            `;
            await sql`
                UPDATE products
                SET stock_quantity = GREATEST(stock_quantity - ${item.quantity}, 0)
                WHERE id = ${item.product_id}
            `;
        }

        clearPublicCache("products");

        await recordOrderEvent(
            order.id,
            "order_placed",
            null,
            "pending",
            note || "Order placed and awaiting admin approval.",
            `customer:${customerId}`,
            { delivery_location: shippingAddress, tracking_number: trackingNumber }
        );

        res.setHeader("Cache-Control", "no-store");
        return res.status(201).json({
            success: true,
            message: "Order placed successfully.",
            order: {
                ...order,
                items: resolvedItems
            }
        });
    } catch (error) {
        console.error("Create order error:", error);
        return bad(res, "Could not place order.", 500);
    }
});

app.get("/api/customer/orders", requireCustomer, async (req, res) => {
    try {
        const orders = await sql`
            SELECT *
            FROM orders
            WHERE customer_id = ${req.customer.id}
            ORDER BY id DESC
        `;

        const orderIds = orders.map(o => o.id);
        let eventsByOrder = new Map();
        let itemsByOrder = new Map();

        if (orderIds.length > 0) {
            const events = await sql`
                SELECT *
                FROM order_events
                WHERE order_id = ANY(${orderIds})
                ORDER BY created_at ASC, id ASC
            `;
            for (const ev of events) {
                if (!eventsByOrder.has(String(ev.order_id))) eventsByOrder.set(String(ev.order_id), []);
                eventsByOrder.get(String(ev.order_id)).push(ev);
            }

            const items = await sql`
                SELECT *
                FROM order_items
                WHERE order_id = ANY(${orderIds})
                ORDER BY id ASC
            `;
            for (const it of items) {
                if (!itemsByOrder.has(String(it.order_id))) itemsByOrder.set(String(it.order_id), []);
                itemsByOrder.get(String(it.order_id)).push(it);
            }
        }

        const enriched = orders.map(o => ({
            ...o,
            items: itemsByOrder.get(String(o.id)) || [],
            timeline: eventsByOrder.get(String(o.id)) || []
        }));

        res.setHeader("Cache-Control", "no-store");
        return res.json({ success: true, orders: enriched });
    } catch (error) {
        console.error("Customer orders error:", error);
        return bad(res, "Could not load your orders.", 500);
    }
});

// Public / Customer / Tracking Timeline endpoint (by order ID or tracking number)
app.get("/api/orders/track", async (req, res) => {
    try {
        const orderIdParam = str(req.query.order_id || req.query.id || "");
        const trackingParam = str(req.query.tracking_number || req.query.tracking || "");
        const phoneParam = normalizePhone(req.query.phone || "");

        if (!orderIdParam && !trackingParam) {
            return bad(res, "Please provide order_id or tracking_number.");
        }

        let rows = [];
        if (trackingParam) {
            rows = await sql`
                SELECT * FROM orders WHERE UPPER(tracking_number) = UPPER(${trackingParam}) LIMIT 1
            `;
        } else if (isValidId(orderIdParam)) {
            rows = await sql`
                SELECT * FROM orders WHERE id = ${orderIdParam} LIMIT 1
            `;
        } else {
            return bad(res, "Invalid order reference.");
        }

        if (!rows.length) return bad(res, "Order not found.", 404);
        const order = rows[0];

        if (phoneParam && normalizePhone(order.customer_phone) !== phoneParam) {
            return bad(res, "Phone number does not match this order.", 403);
        }

        const timeline = await sql`
            SELECT
                id, order_id, event_type, old_value, new_value, note, actor,
                delivery_location, tracking_number, courier_name, gps_lat, gps_lng, created_at
            FROM order_events
            WHERE order_id = ${order.id}
            ORDER BY created_at ASC, id ASC
        `;

        return res.json({
            success: true,
            order: {
                id: order.id,
                tracking_number: order.tracking_number,
                status: order.status,
                approval_status: order.approval_status,
                delivery_status: order.delivery_status,
                supplier_progress: order.supplier_progress,
                delivery_location: order.delivery_location,
                delivery_note: order.delivery_note,
                delivery_name: order.delivery_name,
                delivery_phone: order.delivery_phone,
                courier_name: order.courier_name,
                gps_lat: order.gps_lat,
                gps_lng: order.gps_lng,
                gps_updated_at: order.gps_updated_at,
                delivered_at: order.delivered_at,
                delivery_updated_at: order.delivery_updated_at,
                created_at: order.created_at
            },
            timeline
        });
    } catch (error) {
        console.error("Order tracking error:", error);
        return bad(res, "Could not load tracking details.", 500);
    }
});

// =====================================
// CONTACT MESSAGES
// =====================================

app.post("/api/contact", contactLimiter, optionalCustomer, async (req, res) => {
    try {
        const { name, email, phone, subject, message, order_id } = req.body || {};
        const cleanName = str(name);
        const cleanEmail = str(email).toLowerCase();
        const cleanPhone = normalizePhone(phone || "");
        const cleanSubject = str(subject || "General Inquiry");
        const cleanMessage = str(message);
        const cleanOrderId = order_id && isValidId(String(order_id)) ? Number(order_id) : null;

        if (!cleanName || cleanName.length > 150) return bad(res, "Please enter your name.");
        if (!cleanEmail || !EMAIL_REGEX.test(cleanEmail) || cleanEmail.length > 255) {
            return bad(res, "Please enter a valid email address.");
        }
        if (!cleanMessage || cleanMessage.length > 2000) {
            return bad(res, "Please enter a message.");
        }

        const inserted = await sql`
            INSERT INTO messages (customer_id, order_id, name, email, phone, subject, message)
            VALUES (
                ${req.customer ? req.customer.id : null},
                ${cleanOrderId},
                ${cleanName},
                ${cleanEmail},
                ${cleanPhone || null},
                ${cleanSubject.slice(0, 200)},
                ${cleanMessage}
            )
            RETURNING *
        `;

        return res.status(201).json({ success: true, message: "Message sent successfully.", data: inserted[0] });
    } catch (error) {
        console.error("Contact error:", error);
        return bad(res, "Could not send message.", 500);
    }
});

// =====================================
// ADMIN MESSAGES API ROUTES
// =====================================

// 1. GET ALL MESSAGES
app.get("/api/admin/messages", requireAdmin, async (req, res) => {
    try {
        const rows = await sql`
            SELECT *
            FROM messages
            ORDER BY created_at DESC
        `;

        return res.json({
            success: true,
            messages: rows
        });
    } catch (error) {
        console.error("Get messages error:", error);
        return bad(res, "Could not load messages.", 500);
    }
});


// 2. GET SINGLE MESSAGE
app.get("/api/admin/messages/:id", requireAdmin, async (req, res) => {
    try {
        const id = String(req.params.id);

        if (!isValidId(id)) {
            return bad(res, "Invalid message ID.", 400);
        }

        const rows = await sql`
            SELECT *
            FROM messages
            WHERE id = ${Number(id)}
            LIMIT 1
        `;

        if (!rows.length) {
            return bad(res, "Message not found.", 404);
        }

        return res.json({
            success: true,
            message: rows[0]
        });
    } catch (error) {
        console.error("Get single message error:", error);
        return bad(res, "Could not load message.", 500);
    }
});


// 3. UPDATE MESSAGE STATUS
app.patch("/api/admin/messages/:id/status", requireAdmin, async (req, res) => {
    try {
        const id = String(req.params.id);
        const status = str(req.body?.status).toLowerCase();

        if (!isValidId(id)) {
            return bad(res, "Invalid message ID.", 400);
        }

        if (!["read", "unread"].includes(status)) {
            return bad(res, "Status must be read or unread.", 400);
        }

        const rows = await sql`
            UPDATE messages
            SET status = ${status}
            WHERE id = ${Number(id)}
            RETURNING *
        `;

        if (!rows.length) {
            return bad(res, "Message not found.", 404);
        }

        return res.json({
            success: true,
            message: "Message status updated.",
            data: rows[0]
        });
    } catch (error) {
        console.error("Update message status error:", error);
        return bad(res, "Could not update message status.", 500);
    }
});


// 4. DELETE MESSAGE
app.delete("/api/admin/messages/:id", requireAdmin, async (req, res) => {
    try {
        const id = String(req.params.id);

        if (!isValidId(id)) {
            return bad(res, "Invalid message ID.", 400);
        }

        const rows = await sql`
            DELETE FROM messages
            WHERE id = ${Number(id)}
            RETURNING id
        `;

        if (!rows.length) {
            return bad(res, "Message not found.", 404);
        }

        return res.json({
            success: true,
            message: "Message deleted successfully."
        });
    } catch (error) {
        console.error("Delete message error:", error);
        return bad(res, "Could not delete message.", 500);
    }
});


// =====================================
// SUPPLIER ORDER PROGRESS & PRODUCT LINKS ROUTES
// =====================================


app.get("/api/supplier/orders", supplierAuth.requireSupplier, async (req, res) => {
    try {
        const supplierId = req.supplier.id;
        const orders = await sql`
            SELECT DISTINCT o.*
            FROM orders o
            LEFT JOIN order_items oi ON oi.order_id = o.id
            LEFT JOIN products p ON p.id = oi.product_id
            WHERE o.supplier_id = ${supplierId} OR p.supplier_id = ${supplierId}
            ORDER BY o.id DESC
        `;
        return res.json({ success: true, orders });
    } catch (error) {
        console.error("Supplier orders error:", error);
        return bad(res, "Could not load supplier orders.", 500);
    }
});

app.patch("/api/supplier/orders/:id/progress", supplierAuth.requireSupplier, async (req, res) => {
    try {
        if (!isValidId(req.params.id)) return bad(res, "Invalid order ID.");

        const { progress_status, delivery_status, note } = req.body || {};
        const nextProgress = str(progress_status || delivery_status).toLowerCase();
        const cleanNote = str(note || "");

        const validSupplierStatuses = ["preparing", "ready_for_dispatch", "shipped", "delivered", ...SUPPLIER_DELIVERY_ALLOWED];
        if (!validSupplierStatuses.includes(nextProgress)) {
            return bad(res, "Invalid supplier progress status.");
        }

        const rows = await sql`
            SELECT o.*
            FROM orders o
            LEFT JOIN order_items oi ON oi.order_id = o.id
            LEFT JOIN products p ON p.id = oi.product_id
            WHERE o.id = ${req.params.id}
              AND (o.supplier_id = ${req.supplier.id} OR p.supplier_id = ${req.supplier.id})
            LIMIT 1
        `;
        if (!rows.length) return bad(res, "Order not found or not assigned to you.", 404);

        const order = rows[0];
        if (order.approval_status === "rejected" || order.status === "cancelled") {
            return bad(res, "Cannot update progress for a rejected or cancelled order.", 400);
        }

        const mappedDeliveryStatus = nextProgress === "preparing" ? "processing" : nextProgress;
        const mappedOrderStatus = nextProgress === "delivered"
            ? "delivered"
            : (nextProgress === "shipped" ? "shipped" : "processing");

        const updated = await sql`
            UPDATE orders
            SET supplier_progress = ${nextProgress},
                supplier_note = ${cleanNote || order.supplier_note},
                supplier_updated_at = NOW(),
                delivery_status = ${mappedDeliveryStatus},
                status = CASE WHEN status IN ('rejected', 'cancelled') THEN status ELSE ${mappedOrderStatus} END,
                delivery_updated_at = NOW(),
                delivered_at = CASE WHEN ${nextProgress} = 'delivered' THEN COALESCE(delivered_at, NOW()) ELSE delivered_at END
            WHERE id = ${order.id}
            RETURNING *
        `;

        await recordOrderEvent(
            order.id,
            "supplier_progress",
            order.supplier_progress || order.delivery_status,
            nextProgress,
            cleanNote || `Supplier updated status to ${nextProgress}.`,
            `supplier:${req.supplier.id}`,
            { tracking_number: order.tracking_number, delivery_location: order.delivery_location }
        );

        return res.json({ success: true, message: "Supplier progress updated.", order: updated[0] });
    } catch (error) {
        console.error("Supplier order progress error:", error);
        return bad(res, "Could not update supplier progress.", 500);
    }
});

// Supplier product links management (up to 25 links per product)
app.get("/api/supplier/products/:productId/links", supplierAuth.requireSupplier, async (req, res) => {
    try {
        if (!isValidId(req.params.productId)) return bad(res, "Invalid product ID.");
        const prod = await sql`
            SELECT id FROM products WHERE id = ${req.params.productId} AND supplier_id = ${req.supplier.id} LIMIT 1
        `;
        if (!prod.length) return bad(res, "Product not found or access denied.", 404);

        const links = await sql`
            SELECT * FROM product_links WHERE product_id = ${req.params.productId} ORDER BY sort_order ASC, id ASC
        `;
        return res.json({ success: true, links });
    } catch (error) {
        console.error("Supplier product links list error:", error);
        return bad(res, "Could not load product links.", 500);
    }
});

app.post("/api/supplier/products/:productId/links", supplierAuth.requireSupplier, async (req, res) => {
    try {
        if (!isValidId(req.params.productId)) return bad(res, "Invalid product ID.");
        const prod = await sql`
            SELECT id FROM products WHERE id = ${req.params.productId} AND supplier_id = ${req.supplier.id} LIMIT 1
        `;
        if (!prod.length) return bad(res, "Product not found or access denied.", 404);

        const existingCount = await sql`
            SELECT COUNT(*)::int AS cnt FROM product_links WHERE product_id = ${req.params.productId}
        `;
        if ((existingCount[0]?.cnt || 0) >= MAX_PRODUCT_LINKS) {
            return bad(res, `Maximum ${MAX_PRODUCT_LINKS} links allowed per product.`);
        }

        const title = str(req.body?.title || req.body?.name || "Link").slice(0, 120);
        const url = str(req.body?.url || "");
        if (!url || !isSafeHttpUrl(url)) return bad(res, "Please provide a valid HTTP/HTTPS URL.");

        const platform = str(req.body?.platform || detectPlatformFromUrl(url)).slice(0, 50);

        const inserted = await sql`
            INSERT INTO product_links (product_id, title, url, platform, visibility, created_by_role, created_by_id)
            VALUES (${req.params.productId}, ${title}, ${url}, ${platform}, 'public', 'supplier', ${req.supplier.id})
            RETURNING *
        `;
        clearPublicCache("products");
        return res.status(201).json({ success: true, message: "Link added.", link: inserted[0] });
    } catch (error) {
        console.error("Supplier add link error:", error);
        return bad(res, "Could not add link.", 500);
    }
});

app.put("/api/supplier/links/:linkId", supplierAuth.requireSupplier, async (req, res) => {
    try {
        if (!isValidId(req.params.linkId)) return bad(res, "Invalid link ID.");
        const rows = await sql`
            SELECT pl.*
            FROM product_links pl
            JOIN products p ON p.id = pl.product_id
            WHERE pl.id = ${req.params.linkId} AND p.supplier_id = ${req.supplier.id}
            LIMIT 1
        `;
        if (!rows.length) return bad(res, "Link not found or access denied.", 404);

        const current = rows[0];
        const title = req.body?.title !== undefined ? str(req.body.title).slice(0, 120) : current.title;
        const url = req.body?.url !== undefined ? str(req.body.url) : current.url;
        if (!url || !isSafeHttpUrl(url)) return bad(res, "Please provide a valid HTTP/HTTPS URL.");

        const platform = req.body?.platform !== undefined ? str(req.body.platform).slice(0, 50) : detectPlatformFromUrl(url);

        const updated = await sql`
            UPDATE product_links
            SET title = ${title || "Link"}, url = ${url}, platform = ${platform}, updated_at = NOW()
            WHERE id = ${current.id}
            RETURNING *
        `;
        clearPublicCache("products");
        return res.json({ success: true, message: "Link updated.", link: updated[0] });
    } catch (error) {
        console.error("Supplier update link error:", error);
        return bad(res, "Could not update link.", 500);
    }
});

app.delete("/api/supplier/links/:linkId", supplierAuth.requireSupplier, async (req, res) => {
    try {
        if (!isValidId(req.params.linkId)) return bad(res, "Invalid link ID.");
        const deleted = await sql`
            DELETE FROM product_links pl
            USING products p
            WHERE pl.id = ${req.params.linkId}
              AND pl.product_id = p.id
              AND p.supplier_id = ${req.supplier.id}
            RETURNING pl.id
        `;
        if (!deleted.length) return bad(res, "Link not found or access denied.", 404);
        clearPublicCache("products");
        return res.json({ success: true, message: "Link deleted." });
    } catch (error) {
        console.error("Supplier delete link error:", error);
        return bad(res, "Could not delete link.", 500);
    }
});

// =====================================
// ADMIN AUTHENTICATION & DASHBOARD
// =====================================

app.post("/api/admin/login", adminLoginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body || {};
        const cleanEmail = str(email).toLowerCase();
        if (!cleanEmail || typeof password !== "string" || !password) {
            return bad(res, "Please enter email and password.");
        }

        const rows = await sql`
            SELECT id, name, email, role, password_hash, is_active
            FROM admins
            WHERE LOWER(email) = ${cleanEmail}
            LIMIT 1
        `;

        const admin = rows[0] || null;
        const hashToCheck = admin && admin.password_hash ? admin.password_hash : DUMMY_PASSWORD_HASH;
        const match = await bcrypt.compare(password, hashToCheck);

        if (!admin || !admin.is_active || !match) {
            return bad(res, "Invalid admin credentials.", 401);
        }

        const token = jwt.sign(
            { type: "admin", role: admin.role || "admin" },
            JWT_SECRET,
            { subject: String(admin.id), expiresIn: COOKIE_MAX_AGE, algorithm: "HS256" }
        );

        setAdminCookie(res, token);
        return res.json({
            success: true,
            message: "Admin login successful.",
            admin: { id: admin.id, name: admin.name, email: admin.email, role: admin.role }
        });
    } catch (error) {
        console.error("Admin login error:", error);
        return bad(res, "Login failed.", 500);
    }
});

app.post("/api/admin/logout", (req, res) => {
    clearAdminCookie(res);
    return res.json({ success: true, message: "Logged out." });
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
    return res.json({ success: true, admin: req.admin });
});
// =====================================
// ADMIN DASHBOARD STATISTICS
// =====================================

app.get("/api/admin/dashboard-stats", requireAdmin, async (req, res) => {
    try {
        const rows = await sql`
            SELECT
                (SELECT COUNT(*)::int FROM products) AS total_products,
                (SELECT COUNT(*)::int FROM orders) AS total_orders,
                (SELECT COUNT(*)::int FROM customers) AS total_customers,
                (SELECT COUNT(*)::int FROM messages) AS total_messages
        `;

        const stats = rows[0];

        return res.json({
            success: true,
            statistics: {
                totalProducts: stats.total_products,
                totalOrders: stats.total_orders,
                totalCustomers: stats.total_customers,
                totalMessages: stats.total_messages
            }
        });
    } catch (error) {
        console.error("Dashboard statistics error:", error);
        return bad(res, "Could not load dashboard statistics.", 500);
    }
});

// =====================================
// ADMIN IMAGE UPLOAD (Single or up to 4 files)
// =====================================

app.post("/api/admin/upload", requireAdmin, imageUploadLimiter, (req, res) => {
    imageUpload.array("images", MAX_PRODUCT_IMAGES)(req, res, (err) => {
        if (err) {
            return bad(res, err.message || "Image upload failed.");
        }
        const files = req.files || [];
        if (!files.length) return bad(res, "Please select an image file.");

        const urls = [];
        for (const f of files) {
            const ext = allowedImageTypes[f.mimetype] || "jpg";
            const fileName = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}.${ext}`;
            fs.writeFileSync(path.join(uploadDirectory, fileName), f.buffer);
            urls.push(`/uploads/${fileName}`);
        }

        return res.json({
            success: true,
            url: urls[0],
            urls
        });
    });
});

// =====================================
// ADMIN PRODUCTS, GALLERY (MAX 4) & LINKS (MAX 25)
// =====================================

app.get("/api/admin/products", requireAdmin, async (req, res) => {
    try {
        const products = await sql`SELECT * FROM products ORDER BY id DESC`;
        const links = await sql`SELECT * FROM product_links ORDER BY sort_order ASC, id ASC`;
        const linksMap = new Map();
        for (const l of links) {
            if (!linksMap.has(String(l.product_id))) linksMap.set(String(l.product_id), []);
            linksMap.get(String(l.product_id)).push(l);
        }

        const enriched = products.map(p => {
            const gallery = normalizeImageGallery(p.image_urls, p.image_url).slice(0, MAX_PRODUCT_IMAGES);
            return {
                ...p,
                image_url: gallery[0] || p.image_url || "",
                image_urls: gallery,
                links: linksMap.get(String(p.id)) || []
            };
        });

        return res.json({ success: true, products: enriched });
    } catch (error) {
        console.error("Admin products list error:", error);
        return bad(res, "Could not load products.", 500);
    }
});

app.post("/api/admin/products", requireAdmin, async (req, res) => {
    try {
        const body = req.body || {};
        const name = str(body.name);
        const description = str(body.description || "");
        const price = Number(body.price);
        const stockQuantity = body.stock_quantity !== undefined ? Number(body.stock_quantity) : 0;
        const category = str(body.category || "");
        const discountEnabled = Boolean(body.discount_enabled);
        const discountPercent = discountEnabled ? Number(body.discount_percent || 0) : 0;
        const isActive = body.is_active !== undefined ? Boolean(body.is_active) : true;
        const supplierId = body.supplier_id && isValidId(String(body.supplier_id)) ? Number(body.supplier_id) : null;

        if (!name || name.length > 200) return bad(res, "Please enter a valid product name.");
        if (!Number.isFinite(price) || price < 0) return bad(res, "Please enter a valid price.");
        if (!Number.isInteger(stockQuantity) || stockQuantity < 0) return bad(res, "Invalid stock quantity.");

        const gallery = normalizeImageGallery(body.image_urls, body.image_url);
        if (gallery.length > MAX_PRODUCT_IMAGES) {
            return bad(res, `Maximum ${MAX_PRODUCT_IMAGES} images are allowed per product.`);
        }
        const primaryImage = gallery[0] || str(body.image_url) || "";

        const linksList = normalizeLinksInput(body.links);
        if (linksList.length > MAX_PRODUCT_LINKS) {
            return bad(res, `Maximum ${MAX_PRODUCT_LINKS} links are allowed per product.`);
        }

        const inserted = await sql`
            INSERT INTO products (
                name, description, price, discount_enabled, discount_percent,
                stock_quantity, image_url, image_urls, category, is_active, supplier_id
            )
            VALUES (
                ${name}, ${description}, ${price}, ${discountEnabled}, ${discountPercent},
                ${stockQuantity}, ${primaryImage}, ${JSON.stringify(gallery)}::jsonb,
                ${category || null}, ${isActive}, ${supplierId}
            )
            RETURNING *
        `;

        const product = inserted[0];
        const savedLinks = [];
        for (let i = 0; i < linksList.length; i++) {
            const lk = linksList[i];
            const row = await sql`
                INSERT INTO product_links (
                    product_id, title, url, platform, visibility, sort_order, created_by_role, created_by_id
                )
                VALUES (
                    ${product.id}, ${lk.title}, ${lk.url}, ${lk.platform}, ${lk.visibility}, ${i}, 'admin', ${req.admin.id}
                )
                RETURNING *
            `;
            savedLinks.push(row[0]);
        }

        if (category) {
            await sql`INSERT INTO categories (name) VALUES (${category}) ON CONFLICT DO NOTHING`;
            clearPublicCache("categories");
        }
        clearPublicCache("products");

        return res.status(201).json({
            success: true,
            message: "Product created.",
            product: { ...product, image_urls: gallery, links: savedLinks }
        });
    } catch (error) {
        console.error("Admin create product error:", error);
        return bad(res, "Could not create product.", 500);
    }
});

app.put("/api/admin/products/:id", requireAdmin, async (req, res) => {
    try {
        if (!isValidId(req.params.id)) return bad(res, "Invalid product ID.");
        const existingRows = await sql`SELECT * FROM products WHERE id = ${req.params.id} LIMIT 1`;
        if (!existingRows.length) return bad(res, "Product not found.", 404);
        const current = existingRows[0];

        const body = req.body || {};
        const name = body.name !== undefined ? str(body.name) : current.name;
        const description = body.description !== undefined ? str(body.description) : (current.description || "");
        const price = body.price !== undefined ? Number(body.price) : Number(current.price);
        const stockQuantity = body.stock_quantity !== undefined ? Number(body.stock_quantity) : Number(current.stock_quantity);
        const category = body.category !== undefined ? str(body.category) : (current.category || "");
        const discountEnabled = body.discount_enabled !== undefined ? Boolean(body.discount_enabled) : Boolean(current.discount_enabled);
        const discountPercent = discountEnabled
            ? Number(body.discount_percent !== undefined ? body.discount_percent : (current.discount_percent || 0))
            : 0;
        const isActive = body.is_active !== undefined ? Boolean(body.is_active) : Boolean(current.is_active);
        const supplierId = body.supplier_id !== undefined
            ? (body.supplier_id && isValidId(String(body.supplier_id)) ? Number(body.supplier_id) : null)
            : current.supplier_id;

        if (!name || name.length > 200) return bad(res, "Invalid product name.");
        if (!Number.isFinite(price) || price < 0) return bad(res, "Invalid product price.");
        if (!Number.isInteger(stockQuantity) || stockQuantity < 0) return bad(res, "Invalid stock quantity.");

        const currentGallery = normalizeImageGallery(current.image_urls, current.image_url);
        const gallery = (body.image_urls !== undefined || body.image_url !== undefined)
            ? normalizeImageGallery(body.image_urls !== undefined ? body.image_urls : currentGallery, body.image_url !== undefined ? body.image_url : current.image_url)
            : currentGallery;

        if (gallery.length > MAX_PRODUCT_IMAGES) {
            return bad(res, `Maximum ${MAX_PRODUCT_IMAGES} images are allowed per product.`);
        }
        const primaryImage = gallery[0] || "";

        const updated = await sql`
            UPDATE products
            SET name = ${name},
                description = ${description},
                price = ${price},
                discount_enabled = ${discountEnabled},
                discount_percent = ${discountPercent},
                stock_quantity = ${stockQuantity},
                image_url = ${primaryImage},
                image_urls = ${JSON.stringify(gallery)}::jsonb,
                category = ${category || null},
                is_active = ${isActive},
                supplier_id = ${supplierId}
            WHERE id = ${current.id}
            RETURNING *
        `;

        if (Array.isArray(body.links)) {
            const linksList = normalizeLinksInput(body.links);
            if (linksList.length > MAX_PRODUCT_LINKS) {
                return bad(res, `Maximum ${MAX_PRODUCT_LINKS} links are allowed per product.`);
            }
            await sql`DELETE FROM product_links WHERE product_id = ${current.id}`;
            for (let i = 0; i < linksList.length; i++) {
                const lk = linksList[i];
                await sql`
                    INSERT INTO product_links (
                        product_id, title, url, platform, visibility, sort_order, created_by_role, created_by_id
                    )
                    VALUES (
                        ${current.id}, ${lk.title}, ${lk.url}, ${lk.platform}, ${lk.visibility}, ${i}, 'admin', ${req.admin.id}
                    )
                `;
            }
        }

        if (category) {
            await sql`INSERT INTO categories (name) VALUES (${category}) ON CONFLICT DO NOTHING`;
            clearPublicCache("categories");
        }
        clearPublicCache("products");

        const links = await sql`SELECT * FROM product_links WHERE product_id = ${current.id} ORDER BY sort_order ASC, id ASC`;
        return res.json({
            success: true,
            message: "Product updated.",
            product: { ...updated[0], image_urls: gallery, links }
        });
    } catch (error) {
        console.error("Admin update product error:", error);
        return bad(res, "Could not update product.", 500);
    }
});

app.delete("/api/admin/products/:id", requireAdmin, async (req, res) => {
    try {
        if (!isValidId(req.params.id)) return bad(res, "Invalid product ID.");
        await sql`DELETE FROM product_links WHERE product_id = ${req.params.id}`;
        const deleted = await sql`DELETE FROM products WHERE id = ${req.params.id} RETURNING id`;
        if (!deleted.length) return bad(res, "Product not found.", 404);
        clearPublicCache("products");
        return res.json({ success: true, message: "Product deleted." });
    } catch (error) {
        console.error("Admin delete product error:", error);
        return bad(res, "Could not delete product.", 500);
    }
});

// Admin dedicated Product Links CRUD (max 25, Public/Private visibility toggle)
app.get("/api/admin/products/:productId/links", requireAdmin, async (req, res) => {
    try {
        if (!isValidId(req.params.productId)) return bad(res, "Invalid product ID.");
        const links = await sql`
            SELECT * FROM product_links WHERE product_id = ${req.params.productId} ORDER BY sort_order ASC, id ASC
        `;
        return res.json({ success: true, links });
    } catch (error) {
        console.error("Admin get links error:", error);
        return bad(res, "Could not load links.", 500);
    }
});

app.post("/api/admin/products/:productId/links", requireAdmin, async (req, res) => {
    try {
        if (!isValidId(req.params.productId)) return bad(res, "Invalid product ID.");
        const prod = await sql`SELECT id FROM products WHERE id = ${req.params.productId} LIMIT 1`;
        if (!prod.length) return bad(res, "Product not found.", 404);

        const countRows = await sql`
            SELECT COUNT(*)::int AS cnt FROM product_links WHERE product_id = ${req.params.productId}
        `;
        if ((countRows[0]?.cnt || 0) >= MAX_PRODUCT_LINKS) {
            return bad(res, `Maximum ${MAX_PRODUCT_LINKS} links allowed per product.`);
        }

        const title = str(req.body?.title || req.body?.name || "Link").slice(0, 120);
        const url = str(req.body?.url || "");
        if (!url || !isSafeHttpUrl(url)) return bad(res, "Please provide a valid HTTP/HTTPS URL.");

        const visibility = str(req.body?.visibility || (req.body?.is_public === false ? "private" : "public")).toLowerCase() === "private"
            ? "private"
            : "public";
        const platform = str(req.body?.platform || detectPlatformFromUrl(url)).slice(0, 50);

        const inserted = await sql`
            INSERT INTO product_links (
                product_id, title, url, platform, visibility, created_by_role, created_by_id
            )
            VALUES (
                ${req.params.productId}, ${title}, ${url}, ${platform}, ${visibility}, 'admin', ${req.admin.id}
            )
            RETURNING *
        `;
        clearPublicCache("products");
        return res.status(201).json({ success: true, message: "Link added.", link: inserted[0] });
    } catch (error) {
        console.error("Admin add link error:", error);
        return bad(res, "Could not add link.", 500);
    }
});

app.put("/api/admin/links/:linkId", requireAdmin, async (req, res) => {
    try {
        if (!isValidId(req.params.linkId)) return bad(res, "Invalid link ID.");
        const rows = await sql`SELECT * FROM product_links WHERE id = ${req.params.linkId} LIMIT 1`;
        if (!rows.length) return bad(res, "Link not found.", 404);
        const cur = rows[0];

        const title = req.body?.title !== undefined ? str(req.body.title).slice(0, 120) : cur.title;
        const url = req.body?.url !== undefined ? str(req.body.url) : cur.url;
        if (!url || !isSafeHttpUrl(url)) return bad(res, "Please provide a valid HTTP/HTTPS URL.");

        const rawVis = req.body?.visibility !== undefined
            ? str(req.body.visibility).toLowerCase()
            : (req.body?.is_public !== undefined ? (req.body.is_public ? "public" : "private") : cur.visibility);
        const visibility = rawVis === "private" ? "private" : "public";
        const platform = req.body?.platform !== undefined ? str(req.body.platform).slice(0, 50) : detectPlatformFromUrl(url);

        const updated = await sql`
            UPDATE product_links
            SET title = ${title || "Link"}, url = ${url}, platform = ${platform}, visibility = ${visibility}, updated_at = NOW()
            WHERE id = ${cur.id}
            RETURNING *
        `;
        clearPublicCache("products");
        return res.json({ success: true, message: "Link updated.", link: updated[0] });
    } catch (error) {
        console.error("Admin update link error:", error);
        return bad(res, "Could not update link.", 500);
    }
});

app.delete("/api/admin/links/:linkId", requireAdmin, async (req, res) => {
    try {
        if (!isValidId(req.params.linkId)) return bad(res, "Invalid link ID.");
        const deleted = await sql`DELETE FROM product_links WHERE id = ${req.params.linkId} RETURNING id`;
        if (!deleted.length) return bad(res, "Link not found.", 404);
        clearPublicCache("products");
        return res.json({ success: true, message: "Link deleted." });
    } catch (error) {
        console.error("Admin delete link error:", error);
        return bad(res, "Could not delete link.", 500);
    }
});

// =====================================
// ADMIN ORDER APPROVAL, DELIVERY & GPS / COURIER API
// =====================================

app.get("/api/admin/orders", requireAdmin, async (req, res) => {
    try {
        const orders = await sql`SELECT * FROM orders ORDER BY id DESC`;
        const orderIds = orders.map(o => o.id);
        let eventsByOrder = new Map();

        if (orderIds.length > 0) {
            const events = await sql`
                SELECT * FROM order_events
                WHERE order_id = ANY(${orderIds})
                ORDER BY created_at ASC, id ASC
            `;
            for (const ev of events) {
                if (!eventsByOrder.has(String(ev.order_id))) eventsByOrder.set(String(ev.order_id), []);
                eventsByOrder.get(String(ev.order_id)).push(ev);
            }
        }

        const enriched = orders.map(o => ({
            ...o,
            timeline: eventsByOrder.get(String(o.id)) || []
        }));

        return res.json({ success: true, orders: enriched });
    } catch (error) {
        console.error("Admin orders list error:", error);
        return bad(res, "Could not load orders.", 500);
    }
});

// Admin Order Approval / Rejection & Status Change
app.patch("/api/admin/orders/:id/approval", requireAdmin, async (req, res) => {
    try {
        if (!isValidId(req.params.id)) return bad(res, "Invalid order ID.");
        const rows = await sql`SELECT * FROM orders WHERE id = ${req.params.id} LIMIT 1`;
        if (!rows.length) return bad(res, "Order not found.", 404);
        const order = rows[0];

        const decision = str(req.body?.approval_status || req.body?.action || req.body?.status).toLowerCase();
        const note = str(req.body?.note || req.body?.approval_note || "");

        if (!["approved", "rejected", "pending"].includes(decision)) {
            return bad(res, "Invalid approval status. Use approved, rejected, or pending.");
        }

        const nextOrderStatus = decision === "approved"
            ? (order.status === "pending" ? "confirmed" : order.status)
            : (decision === "rejected" ? "cancelled" : "pending");

        const nextDeliveryStatus = decision === "approved"
            ? (order.delivery_status === "pending" ? "order_confirmed" : order.delivery_status)
            : order.delivery_status;

        const updated = await sql`
            UPDATE orders
            SET approval_status = ${decision},
                approval_note = ${note || order.approval_note},
                approved_at = CASE WHEN ${decision} = 'approved' THEN NOW() ELSE approved_at END,
                approved_by = ${req.admin.email || req.admin.name || "admin"},
                status = ${nextOrderStatus},
                delivery_status = ${nextDeliveryStatus},
                delivery_updated_at = NOW()
            WHERE id = ${order.id}
            RETURNING *
        `;

        await recordOrderEvent(
            order.id,
            "order_approval",
            order.approval_status,
            decision,
            note || `Order ${decision} by admin.`,
            `admin:${req.admin.id}`,
            { tracking_number: order.tracking_number, delivery_location: order.delivery_location }
        );

        return res.json({ success: true, message: `Order ${decision}.`, order: updated[0] });
    } catch (error) {
        console.error("Admin order approval error:", error);
        return bad(res, "Could not update order approval.", 500);
    }
});

app.patch("/api/admin/orders/:id/status", requireAdmin, async (req, res) => {
    try {
        if (!isValidId(req.params.id)) return bad(res, "Invalid order ID.");
        const rows = await sql`SELECT * FROM orders WHERE id = ${req.params.id} LIMIT 1`;
        if (!rows.length) return bad(res, "Order not found.", 404);
        const order = rows[0];

        const nextStatus = str(req.body?.status).toLowerCase();
        const note = str(req.body?.note || "");
        if (!ORDER_STATUSES.includes(nextStatus)) {
            return bad(res, "Invalid order status.");
        }

        const nextApproval = nextStatus === "rejected"
            ? "rejected"
            : (["confirmed", "approved", "processing", "shipped", "out_for_delivery", "delivered"].includes(nextStatus)
                ? "approved"
                : order.approval_status);

        const updated = await sql`
            UPDATE orders
            SET status = ${nextStatus},
                approval_status = ${nextApproval},
                delivered_at = CASE WHEN ${nextStatus} = 'delivered' THEN COALESCE(delivered_at, NOW()) ELSE delivered_at END,
                delivery_updated_at = NOW()
            WHERE id = ${order.id}
            RETURNING *
        `;

        await recordOrderEvent(
            order.id,
            "order_status",
            order.status,
            nextStatus,
            note || `Order status changed to ${nextStatus}.`,
            `admin:${req.admin.id}`,
            { tracking_number: order.tracking_number, delivery_location: order.delivery_location }
        );

        return res.json({ success: true, message: "Order status updated.", order: updated[0] });
    } catch (error) {
        console.error("Admin order status error:", error);
        return bad(res, "Could not update order status.", 500);
    }
});

// Admin Delivery Management (Delivery Status, Location, Note, Delivery Person, Tracking #, GPS & Courier API)
app.patch("/api/admin/orders/:id/delivery", requireAdmin, async (req, res) => {
    try {
        if (!isValidId(req.params.id)) return bad(res, "Invalid order ID.");
        const rows = await sql`SELECT * FROM orders WHERE id = ${req.params.id} LIMIT 1`;
        if (!rows.length) return bad(res, "Order not found.", 404);
        const order = rows[0];

        const body = req.body || {};
        const nextDeliveryStatus = body.delivery_status !== undefined
            ? str(body.delivery_status).toLowerCase()
            : order.delivery_status;

        if (!DELIVERY_STATUSES.includes(nextDeliveryStatus)) {
            return bad(res, "Invalid delivery status.");
        }

        const deliveryLocation = body.delivery_location !== undefined
            ? str(body.delivery_location)
            : (order.delivery_location || "");
        const deliveryNote = body.delivery_note !== undefined
            ? str(body.delivery_note)
            : (body.note !== undefined ? str(body.note) : (order.delivery_note || ""));
        const deliveryName = body.delivery_name !== undefined
            ? str(body.delivery_name)
            : (order.delivery_name || "");
        const deliveryPhone = body.delivery_phone !== undefined
            ? str(body.delivery_phone)
            : (order.delivery_phone || "");
        const trackingNumber = body.tracking_number !== undefined
            ? str(body.tracking_number)
            : (order.tracking_number || "");
        const courierName = body.courier_name !== undefined
            ? str(body.courier_name)
            : (order.courier_name || "");
        const courierApiRef = body.courier_api_ref !== undefined
            ? str(body.courier_api_ref)
            : (order.courier_api_ref || "");

        const gpsLat = (body.gps_lat !== undefined && body.gps_lat !== null && body.gps_lat !== "")
            ? Number(body.gps_lat)
            : order.gps_lat;
        const gpsLng = (body.gps_lng !== undefined && body.gps_lng !== null && body.gps_lng !== "")
            ? Number(body.gps_lng)
            : order.gps_lng;

        if (gpsLat !== null && gpsLat !== undefined && (!Number.isFinite(gpsLat) || gpsLat < -90 || gpsLat > 90)) {
            return bad(res, "Invalid GPS latitude.");
        }
        if (gpsLng !== null && gpsLng !== undefined && (!Number.isFinite(gpsLng) || gpsLng < -180 || gpsLng > 180)) {
            return bad(res, "Invalid GPS longitude.");
        }

        const gpsUpdated = (body.gps_lat !== undefined || body.gps_lng !== undefined);

        const mappedOrderStatus = nextDeliveryStatus === "delivered"
            ? "delivered"
            : (nextDeliveryStatus === "shipped"
                ? "shipped"
                : (nextDeliveryStatus === "out_for_delivery" ? "out_for_delivery" : order.status));

        const updated = await sql`
            UPDATE orders
            SET delivery_status = ${nextDeliveryStatus},
                delivery_location = ${deliveryLocation || null},
                delivery_note = ${deliveryNote || null},
                delivery_name = ${deliveryName || null},
                delivery_phone = ${deliveryPhone || null},
                tracking_number = ${trackingNumber || null},
                tracking_info = ${deliveryNote || deliveryLocation || order.tracking_info},
                courier_name = ${courierName || null},
                courier_api_ref = ${courierApiRef || null},
                gps_lat = ${gpsLat ?? null},
                gps_lng = ${gpsLng ?? null},
                gps_updated_at = CASE WHEN ${gpsUpdated} THEN NOW() ELSE gps_updated_at END,
                status = ${mappedOrderStatus},
                delivered_at = CASE WHEN ${nextDeliveryStatus} = 'delivered' THEN COALESCE(delivered_at, NOW()) ELSE delivered_at END,
                delivery_updated_at = NOW()
            WHERE id = ${order.id}
            RETURNING *
        `;

        await recordOrderEvent(
            order.id,
            "delivery_update",
            order.delivery_status,
            nextDeliveryStatus,
            deliveryNote || `Delivery updated: ${nextDeliveryStatus}${deliveryLocation ? ` (${deliveryLocation})` : ""}`,
            `admin:${req.admin.id}`,
            {
                delivery_location: deliveryLocation || null,
                tracking_number: trackingNumber || null,
                courier_name: courierName || null,
                gps_lat: gpsLat ?? null,
                gps_lng: gpsLng ?? null
            }
        );

        return res.json({ success: true, message: "Delivery information updated.", order: updated[0] });
    } catch (error) {
        console.error("Admin delivery update error:", error);
        return bad(res, "Could not update delivery details.", 500);
    }
});

// Future-ready Courier API Sync / Webhook endpoint for Admin
app.post("/api/admin/orders/:id/courier-sync", requireAdmin, async (req, res) => {
    try {
        if (!isValidId(req.params.id)) return bad(res, "Invalid order ID.");
        const rows = await sql`SELECT * FROM orders WHERE id = ${req.params.id} LIMIT 1`;
        if (!rows.length) return bad(res, "Order not found.", 404);
        const order = rows[0];

        const settings = await getSettings(true);
        const provider = str(req.body?.courier_provider || order.courier_name || settings.courier_provider || "custom");
        const trackingNumber = str(req.body?.tracking_number || order.tracking_number || "");
        const externalStatus = str(req.body?.external_status || order.delivery_status || "shipped").toLowerCase();
        const locationText = str(req.body?.location || order.delivery_location || "In transit via courier");
        const noteText = str(req.body?.note || `Synced from courier (${provider}).`);

        const normalizedStatus = DELIVERY_STATUSES.includes(externalStatus) ? externalStatus : "shipped";

        // If external courier API URL is configured in settings, attempt fetch safely
        let apiResponsePayload = null;
        if (settings.courier_api_enabled === "true" && settings.courier_api_url && trackingNumber && typeof fetch === "function") {
            try {
                const endpoint = new URL(settings.courier_api_url);
                endpoint.searchParams.set("tracking_number", trackingNumber);
                endpoint.searchParams.set("provider", provider);
                const resp = await fetch(endpoint.toString(), { signal: AbortSignal.timeout(5000) });
                if (resp.ok) {
                    apiResponsePayload = await resp.json().catch(() => null);
                }
            } catch (err) {
                console.warn("External courier API call skipped/failed:", err.message);
            }
        }

        const updated = await sql`
            UPDATE orders
            SET courier_name = ${provider},
                tracking_number = ${trackingNumber || order.tracking_number},
                delivery_status = ${normalizedStatus},
                delivery_location = ${locationText},
                delivery_note = ${noteText},
                delivery_updated_at = NOW(),
                delivered_at = CASE WHEN ${normalizedStatus} = 'delivered' THEN COALESCE(delivered_at, NOW()) ELSE delivered_at END
            WHERE id = ${order.id}
            RETURNING *
        `;

        await recordOrderEvent(
            order.id,
            "courier_sync",
            order.delivery_status,
            normalizedStatus,
            noteText,
            `admin:${req.admin.id}`,
            {
                delivery_location: locationText,
                tracking_number: trackingNumber || order.tracking_number,
                courier_name: provider
            }
        );

        return res.json({
            success: true,
            message: "Courier tracking synced.",
            order: updated[0],
            external_api_data: apiResponsePayload
        });
    } catch (error) {
        console.error("Courier sync error:", error);
        return bad(res, "Could not sync courier status.", 500);
    }
});

// =====================================
// ADMIN SETTINGS & CATEGORIES
// =====================================

app.get("/api/admin/settings", requireAdmin, async (req, res) => {
    try {
        const settings = await getSettings(true);
        return res.json({ success: true, settings });
    } catch (error) {
        console.error("Admin get settings error:", error);
        return bad(res, "Could not load settings.", 500);
    }
});

app.put("/api/admin/settings", requireAdmin, async (req, res) => {
    try {
        const body = req.body || {};
        for (const key of SETTING_KEYS) {
            if (body[key] !== undefined) {
                const val = String(body[key]);
                await sql`
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES (${key}, ${val}, NOW())
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
                `;
            }
        }
        clearPublicCache("settings");
        const updated = await getSettings(true);
        return res.json({ success: true, message: "Settings updated.", settings: updated });
    } catch (error) {
        console.error("Admin update settings error:", error);
        return bad(res, "Could not update settings.", 500);
    }
});

// =====================================
// GLOBAL ERROR HANDLER & STARTUP
// =====================================

app.use((err, req, res, next) => {
    console.error("Unhandled server error:", err);
    if (res.headersSent) return next(err);
    return res.status(500).json({ success: false, message: "Internal server error." });
});

async function startServer() {
    try {
        await testConnection();
        await runMigrations();
        app.listen(PORT, () => {
            console.log(`BAZAR GHOR server running on port ${PORT}`);
        });
    } catch (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
}

startServer();