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
// STATUS DEFINITIONS
// =====================================

const ORDER_STATUSES = ["pending", "confirmed", "processing", "shipped", "delivered", "cancelled"];
const PAYMENT_STATUSES = ["unpaid", "pending_verification", "paid", "rejected", "refunded"];
const DELIVERY_STATUSES = [
    "order_confirmed", "processing", "ready_for_delivery", "shipped",
    "out_for_delivery", "delivered", "delivery_failed", "returned"
];
// Delivery steps a supplier is allowed to set (delivered / failed / returned stay admin-only)
const SUPPLIER_DELIVERY_ALLOWED = ["processing", "ready_for_delivery", "shipped", "out_for_delivery"];
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
    publicDataCache.delete(key);
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
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb", parameterLimit: 100 }));

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
    limits: { fileSize: 5 * 1024 * 1024, files: 1 },
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

    // Only admin tokens are accepted (customer / supplier tokens are rejected)
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

// Does not block guests; just attaches req.customer when a valid token exists
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
// SUPPLIER AUTHENTICATION + PRODUCT ROUTER (unchanged modules)
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
// STATIC ASSETS AND UPLOADED IMAGES
// =====================================

app.use("/assets", express.static(path.join(__dirname, "..", "assets"), {
    maxAge: "1d", etag: true, lastModified: true
}));

app.use("/uploads", express.static(uploadDirectory, {
    dotfiles: "deny", index: false, maxAge: "7d", etag: true, lastModified: true
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

    // ---- orders: delivery + payment verification ----
    await step("orders.delivery_status", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_status TEXT NOT NULL DEFAULT 'pending'`);
    await step("orders.delivery_charge", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_charge NUMERIC(12,2) NOT NULL DEFAULT 0`);
    await step("orders.tracking_info", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS tracking_info TEXT`);
    await step("orders.delivered_at", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ`);
    await step("orders.delivery_updated_at", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_updated_at TIMESTAMPTZ`);
    await step("orders.delivery_name", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_name TEXT`);
    await step("orders.delivery_phone", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_phone TEXT`);
    await step("orders.payment_verified_at", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_verified_at TIMESTAMPTZ`);
    await step("orders.payment_verified_by", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_verified_by TEXT`);
    await step("orders.payment_note", () => sql`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_note TEXT`);
    await step("idx orders customer", () => sql`CREATE INDEX IF NOT EXISTS idx_orders_customer_id ON orders (customer_id)`);
    await step("idx order_items order", () => sql`CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items (order_id)`);

    // ---- products: category ----
    await step("products.category", () => sql`ALTER TABLE products ADD COLUMN IF NOT EXISTS category TEXT`);
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

    // ---- settings, order events, supplier messages ----
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
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
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
        await sql`UPDATE orders SET delivered_at = COALESCE(delivered_at, created_at) WHERE status = 'delivered'`;
    });

    // ---- default settings (only inserted if missing) ----
    await step("seed settings", () => {
        const defaults = {
            delivery_charge: String(Number(process.env.DEFAULT_DELIVERY_CHARGE) || 0),
            bkash_number: process.env.BKASH_MERCHANT_NUMBER || "",
            nagad_number: process.env.NAGAD_MERCHANT_NUMBER || "",
            whatsapp_number: process.env.WHATSAPP_NUMBER || "8801933018061",
            facebook_url: process.env.FACEBOOK_URL || ""
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

const SETTING_KEYS = ["delivery_charge", "bkash_number", "nagad_number", "whatsapp_number", "facebook_url"];

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
        facebook_url: ""
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
                nagad_number: "01307359149",
                bkash_number: "01740470179"
            }
        });
    } catch (error) {
        console.error("Public settings error:", error);
        bad(res, "Could not load settings.", 500);
    }
});


// =====================================
// PUBLIC CATEGORIES / PRODUCTS / SERVICES
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
                    p.category
                FROM products p
                WHERE p.is_active = TRUE
                ORDER BY p.id DESC
            `;
            setPublicCache("products", products);
        }

        setPublicCacheHeaders(res);
        return res.json({ success: true, products });
    } catch (error) {
        console.error("Public products error:", error);
        return bad(res, "Could not load products.", 500);
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

        // Another registered account already uses this phone number
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

            // A legacy customer record without a password can be activated only if
            // both the email AND the phone number match.
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
        if (error && error.code === "23505") return bad(res, "This email is already registered.", 409);
        return bad(res, "Registration failed due to a server error.", 500);
    }
}

// the old path is kept as an alias
app.post(["/api/customer/register", "/api/customers/register"], registrationLimiter, handleCustomerRegister);

app.post("/api/customer/login", customerLoginLimiter, async (req, res) => {
    try {
        const body = req.body || {};
        const identifier = str(body.identifier ?? body.email ?? body.phone);
        const password = body.password;

        if (!identifier || identifier.length > 255 || typeof password !== "string" || !password || password.length > 128) {
            return bad(res, "Email/phone and password are required.");
        }

        const emailCandidate = identifier.toLowerCase();
        const phoneCandidate = normalizePhone(identifier);

        const rows = await sql`
            SELECT id, name, email, phone, address, created_at, token_version, password_hash, is_archived
            FROM customers
            WHERE password_hash IS NOT NULL
              AND (LOWER(email) = ${emailCandidate} OR phone = ${phoneCandidate})
            ORDER BY id ASC
            LIMIT 1
        `;

        const customer = rows[0];

        // Always run bcrypt so response time does not reveal whether the account exists
        const matches = await bcrypt.compare(password, customer ? customer.password_hash : DUMMY_PASSWORD_HASH);

        if (!customer || customer.is_archived || !matches) {
            return bad(res, "Invalid email/phone or password.", 401);
        }

        await sql`UPDATE customers SET last_login_at = NOW() WHERE id = ${customer.id}`;

        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            message: "Login successful.",
            token: signCustomerToken(customer),
            customer: publicCustomer(customer)
        });
    } catch (error) {
        console.error("Customer login error:", error);
        return bad(res, "Login failed due to a server error.", 500);
    }
});

app.post("/api/customer/logout", requireCustomer, async (req, res) => {
    try {
        // Raising token_version makes every existing token of this customer invalid
        await sql`UPDATE customers SET token_version = token_version + 1 WHERE id = ${req.customer.id}`;
        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, message: "Logged out successfully." });
    } catch (error) {
        console.error("Customer logout error:", error);
        bad(res, "Could not logout.", 500);
    }
});

app.get("/api/customer/me", requireCustomer, (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.json({ success: true, customer: publicCustomer(req.customer) });
});

app.put("/api/customer/me", requireCustomer, async (req, res) => {
    try {
        const { name, email, phone, address, password } = req.body || {};

        const cleanName = str(name);
        const cleanEmail = str(email).toLowerCase();
        const cleanPhone = normalizePhone(phone);
        const cleanAddress = str(address);

        if (!cleanName || cleanName.length > 150) return bad(res, "Please enter a valid name.");
        if (!cleanEmail || cleanEmail.length > 255 || !EMAIL_REGEX.test(cleanEmail)) {
            return bad(res, "Please enter a valid email address.");
        }
        if (!isValidPhone(cleanPhone)) return bad(res, "Please enter a valid phone number.");
        if (cleanAddress.length > 1000) return bad(res, "Address is too long.");

        const changingPassword = typeof password === "string" && password.length > 0;
        if (changingPassword && (password.length < 6 || password.length > 128)) {
            return bad(res, "Password must be between 6 and 128 characters.");
        }

        const emailTaken = await sql`
            SELECT id FROM customers
            WHERE LOWER(email) = ${cleanEmail} AND id <> ${req.customer.id}
            LIMIT 1
        `;
        if (emailTaken.length) return bad(res, "This email is already used by another account.", 409);

        const phoneTaken = await sql`
            SELECT id FROM customers
            WHERE phone = ${cleanPhone} AND password_hash IS NOT NULL AND id <> ${req.customer.id}
            LIMIT 1
        `;
        if (phoneTaken.length) return bad(res, "This phone number is already used by another account.", 409);

        const newHash = changingPassword ? await bcrypt.hash(password, BCRYPT_ROUNDS) : null;

        const updated = await sql`
            UPDATE customers
            SET name = ${cleanName},
                email = ${cleanEmail},
                phone = ${cleanPhone},
                address = ${cleanAddress || null},
                password_hash = COALESCE(${newHash}::text, password_hash),
                token_version = token_version + ${changingPassword ? 1 : 0}
            WHERE id = ${req.customer.id}
            RETURNING id, name, email, phone, address, created_at, token_version
        `;

        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            message: "Profile updated successfully.",
            customer: publicCustomer(updated[0]),
            // a new token is returned after a password change so the customer stays logged in
            token: changingPassword ? signCustomerToken(updated[0]) : undefined
        });
    } catch (error) {
        console.error("Update customer profile error:", error);
        if (error && error.code === "23505") return bad(res, "This email is already used by another account.", 409);
        return bad(res, "Could not update profile.", 500);
    }
});

// CUSTOMER'S OWN ORDERS (only orders that belong to the logged in customer)
app.get("/api/customer/orders", requireCustomer, async (req, res) => {
    try {
        const orders = await sql`
            SELECT
                id, order_number, total_amount, delivery_charge, status,
                payment_status, payment_method, delivery_status, tracking_info,
                delivery_address, delivered_at, created_at
            FROM orders
            WHERE customer_id = ${req.customer.id}
            ORDER BY id DESC
            LIMIT 200
        `;

        let items = [];

        if (orders.length) {
            const ids = JSON.stringify(orders.map(o => Number(o.id)));
            items = await sql`
                SELECT order_id, product_id, product_name, unit_price, quantity, subtotal
                FROM order_items
                WHERE order_id IN (
                    SELECT value::bigint FROM jsonb_array_elements_text(${ids}::jsonb)
                )
                ORDER BY id ASC
            `;
        }

        const grouped = new Map();
        for (const item of items) {
            const key = String(item.order_id);
            if (!grouped.has(key)) grouped.set(key, []);
            grouped.get(key).push({
                product_id: item.product_id,
                name: item.product_name,
                product_name: item.product_name,
                unit_price: item.unit_price,
                quantity: item.quantity,
                subtotal: item.subtotal
            });
        }

        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            orders: orders.map(o => ({ ...o, items: grouped.get(String(o.id)) || [] }))
        });
    } catch (error) {
        console.error("Customer orders error:", error);
        return bad(res, "Could not load your orders.", 500);
    }
});

// CUSTOMER SUPPORT MESSAGES
app.get("/api/customer/messages", requireCustomer, async (req, res) => {
    try {
        const messages = await sql`
            SELECT id, order_id, subject, message, status, admin_reply, replied_at, created_at
            FROM messages
            WHERE customer_id = ${req.customer.id}
            ORDER BY id DESC
            LIMIT 100
        `;
        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, messages });
    } catch (error) {
        console.error("Customer messages error:", error);
        bad(res, "Could not load your messages.", 500);
    }
});

app.post("/api/customer/messages", requireCustomer, contactLimiter, async (req, res) => {
    try {
        const { order_id, subject, message } = req.body || {};
        const cleanSubject = str(subject);
        const cleanMessage = str(message);

        if (!cleanSubject || cleanSubject.length > 255) return bad(res, "Please enter a subject.");
        if (!cleanMessage || cleanMessage.length > 5000) return bad(res, "Please enter a message.");

        let orderId = null;

        if (order_id !== null && order_id !== undefined && order_id !== "") {
            if (!isValidId(String(order_id))) return bad(res, "Invalid order.");

            // the order must belong to this customer
            const own = await sql`
                SELECT id FROM orders
                WHERE id = ${String(order_id)} AND customer_id = ${req.customer.id}
                LIMIT 1
            `;
            if (!own.length) return bad(res, "Order not found.", 404);
            orderId = own[0].id;
        }

        const result = await sql`
            INSERT INTO messages (name, phone, email, subject, message, status, customer_id, order_id)
            VALUES (
                ${req.customer.name},
                ${req.customer.phone || ""},
                ${req.customer.email || null},
                ${cleanSubject},
                ${cleanMessage},
                'unread',
                ${req.customer.id},
                ${orderId}
            )
            RETURNING id, subject, status, created_at
        `;

        return res.status(201).json({
            success: true,
            message: "Your message has been sent to the admin.",
            data: result[0]
        });
    } catch (error) {
        console.error("Customer message error:", error);
        return bad(res, "Could not send your message.", 500);
    }
});

// =====================================
// PUBLIC CONTACT MESSAGE API
// (/api/contact is kept as an alias because index.html uses it)
// =====================================

app.post(["/api/messages", "/api/contact"], contactLimiter, optionalCustomer, async (req, res) => {
    try {
        const { name, phone, email, subject, message } = req.body || {};

        const cleanName = str(name);
        const cleanPhone = str(phone);
        const cleanEmail = str(email).toLowerCase();
        const cleanSubject = str(subject);
        const cleanMessage = str(message);

        if (!cleanName || cleanName.length > 150) return bad(res, "Please enter a valid name.");
        if (!cleanPhone || cleanPhone.length > 30) return bad(res, "Please enter a valid phone number.");
        if (cleanEmail && (cleanEmail.length > 255 || !EMAIL_REGEX.test(cleanEmail))) {
            return bad(res, "Please enter a valid email address.");
        }
        if (!cleanSubject || cleanSubject.length > 255) return bad(res, "Please enter a subject.");
        if (!cleanMessage || cleanMessage.length > 5000) return bad(res, "Please enter a message.");

        const result = await sql`
            INSERT INTO messages (name, phone, email, subject, message, status, customer_id)
            VALUES (
                ${cleanName},
                ${cleanPhone},
                ${cleanEmail || null},
                ${cleanSubject},
                ${cleanMessage},
                'unread',
                ${req.customer ? req.customer.id : null}
            )
            RETURNING id, name, subject, status, created_at
        `;

        return res.status(201).json({
            success: true,
            message: "Your message has been sent successfully.",
            data: result[0]
        });
    } catch (error) {
        console.error("Contact message submission error:", error);
        return bad(res, "Could not send your message. Please try again.", 500);
    }
});

// =====================================
// CUSTOMER ORDER API
// - works for guests and for logged in customers (Bearer token)
// - prices, discount, stock and delivery charge are always calculated on the server
// =====================================

app.post("/api/orders", orderLimiter, optionalCustomer, async (req, res) => {
    try {
        const body = req.body || {};

        const name = body.name ?? body.customer_name ?? body.customerName;
        const delivery_address = body.delivery_address ?? body.address;
        const payment_reference = body.payment_reference ?? body.transaction_id;

        const cleanName = str(name);
        const cleanEmail = str(body.email).toLowerCase();
        const cleanPhone = normalizePhone(body.phone);
        const cleanAddress = str(delivery_address);
        const cleanPaymentMethod = str(body.payment_method).toLowerCase();
        const cleanReference = str(payment_reference).toUpperCase();
        const items = body.items;

        if (!cleanName || cleanName.length > 150) return bad(res, "Please enter your name.");
        if (!isValidPhone(cleanPhone)) return bad(res, "Please enter a valid phone number.");
        if (!cleanAddress || cleanAddress.length > 1000) return bad(res, "Please enter your delivery address.");
        if (cleanEmail && (cleanEmail.length > 255 || !EMAIL_REGEX.test(cleanEmail))) {
            return bad(res, "Please enter a valid email address.");
        }
        if (!["nagad", "bkash", "cod"].includes(cleanPaymentMethod)) {
            return bad(res, "Please select a valid payment method.");
        }

        const isOnline = ONLINE_METHODS.includes(cleanPaymentMethod);
        const methodLabel = cleanPaymentMethod === "bkash" ? "bKash" : "Nagad";

        if (isOnline) {
            if (!/^[A-Z0-9]{6,30}$/.test(cleanReference)) {
                return bad(res, `Please enter a valid ${methodLabel} Transaction ID (letters and numbers only).`);
            }

            // the same Transaction ID cannot be used for two orders
            const duplicate = await sql`
                SELECT id FROM orders
                WHERE payment_method = ${cleanPaymentMethod}
                  AND UPPER(payment_reference) = ${cleanReference}
                  AND payment_status <> 'rejected'
                LIMIT 1
            `;
            if (duplicate.length) return bad(res, "This Transaction ID has already been used.", 409);

            const settings = await getSettings(true);
            if (!settings[`${cleanPaymentMethod}_number`]) {
                return bad(res, `${methodLabel} payment is not available right now.`, 400);
            }
        }

        if (!Array.isArray(items) || items.length === 0 || items.length > 50) {
            return bad(res, "Your cart is empty or invalid.");
        }

        const itemMap = new Map();

        for (const item of items) {
            const productId = Number(item?.id);
            const quantity = Number(item?.quantity);

            if (
                !Number.isSafeInteger(productId) || productId <= 0 ||
                !Number.isSafeInteger(quantity) || quantity <= 0 || quantity > 100
            ) {
                return bad(res, "Invalid product or quantity.");
            }

            const newQuantity = (itemMap.get(productId) || 0) + quantity;
            if (newQuantity > 100) return bad(res, "Maximum quantity per product is 100.");
            itemMap.set(productId, newQuantity);
        }

        const cleanItems = Array.from(itemMap.entries()).map(([id, quantity]) => ({ product_id: id, quantity }));

        // ---- which customer record does this order belong to? ----
        let existingCustomerId = null;
        let newCustomerEmail = null;

        if (req.customer) {
            existingCustomerId = req.customer.id;
        } else {
            // Guest checkout: reuse an earlier guest record with the same phone number.
            // Registered accounts are never reused for guests (their history stays private).
            const guest = await sql`
                SELECT id FROM customers
                WHERE phone = ${cleanPhone}
                  AND password_hash IS NULL
                  AND is_archived = FALSE
                ORDER BY id DESC
                LIMIT 1
            `;

            if (guest.length) {
                existingCustomerId = guest[0].id;
            } else if (cleanEmail) {
                const emailUsed = await sql`
                    SELECT id FROM customers WHERE LOWER(email) = ${cleanEmail} LIMIT 1
                `;
                newCustomerEmail = emailUsed.length ? null : cleanEmail;
            }
        }

        const settings = await getSettings(true);
        const deliveryCharge = Math.max(0, Number(settings.delivery_charge) || 0);
        const initialPaymentStatus = isOnline ? "pending_verification" : "unpaid";

        const orderNumber = "BG-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex").toUpperCase();

        const result = await sql`
            WITH input_items AS MATERIALIZED (
                SELECT product_id, SUM(quantity)::INTEGER AS quantity
                FROM jsonb_to_recordset(
                    ${JSON.stringify(cleanItems)}::jsonb
                ) AS item(product_id BIGINT, quantity INTEGER)
                GROUP BY product_id
            ),

            checked_items AS MATERIALIZED (
                SELECT
                    p.id,
                    p.name,
                    (
                        CASE
                            WHEN p.discount_enabled = TRUE AND p.discount_percent > 0
                            THEN ROUND(p.price * (1 - p.discount_percent / 100.0), 2)
                            ELSE p.price
                        END
                    )::NUMERIC(12, 2) AS price,
                    i.quantity,
                    (
                        (
                            CASE
                                WHEN p.discount_enabled = TRUE AND p.discount_percent > 0
                                THEN ROUND(p.price * (1 - p.discount_percent / 100.0), 2)
                                ELSE p.price
                            END
                        ) * i.quantity
                    )::NUMERIC(12, 2) AS subtotal
                FROM input_items i
                INNER JOIN products p ON p.id = i.product_id
                WHERE p.is_active = TRUE
            ),

            validation AS MATERIALIZED (
                SELECT
                    COUNT(*)::INTEGER AS item_count,
                    (SELECT COUNT(*) FROM input_items)::INTEGER AS requested_count,
                    COALESCE(BOOL_AND(p.stock_quantity >= ci.quantity), FALSE) AS enough_stock
                FROM checked_items ci
                INNER JOIN products p ON p.id = ci.id
            ),

            updated_stock AS (
                UPDATE products p
                SET stock_quantity = p.stock_quantity - ci.quantity,
                    updated_at = NOW()
                FROM checked_items ci, validation v
                WHERE p.id = ci.id
                  AND v.item_count > 0
                  AND v.item_count = v.requested_count
                  AND v.enough_stock = TRUE
                  AND p.stock_quantity >= ci.quantity
                RETURNING p.id
            ),

            existing_customer AS (
                SELECT c.id
                FROM customers c, validation v
                WHERE c.id = ${existingCustomerId}::BIGINT
                  AND v.item_count > 0
                  AND v.item_count = v.requested_count
                  AND v.enough_stock = TRUE
                  AND (SELECT COUNT(*) FROM updated_stock) = v.item_count
            ),

            inserted_customer AS (
                INSERT INTO customers (name, email, phone)
                SELECT ${cleanName}, ${newCustomerEmail}, ${cleanPhone}
                FROM validation v
                WHERE ${existingCustomerId}::BIGINT IS NULL
                  AND v.item_count > 0
                  AND v.item_count = v.requested_count
                  AND v.enough_stock = TRUE
                  AND (SELECT COUNT(*) FROM updated_stock) = v.item_count
                RETURNING id
            ),

            new_customer AS (
                SELECT id FROM existing_customer
                UNION ALL
                SELECT id FROM inserted_customer
            ),

            new_order AS (
                INSERT INTO orders (
                    customer_id, order_number, total_amount, delivery_charge,
                    status, payment_status, payment_method, payment_reference,
                    delivery_status, delivery_address, delivery_name, delivery_phone
                )
                SELECT
                    c.id,
                    ${orderNumber},
                    (SELECT SUM(subtotal) FROM checked_items) + ${deliveryCharge}::NUMERIC,
                    ${deliveryCharge}::NUMERIC,
                    'pending',
                    ${initialPaymentStatus},
                    ${cleanPaymentMethod},
                    ${isOnline ? cleanReference : null},
                    'pending',
                    ${cleanAddress},
                    ${cleanName},
                    ${cleanPhone}
                FROM new_customer c
                RETURNING
                    id, order_number, total_amount, delivery_charge, status,
                    payment_status, payment_method, delivery_status, created_at
            ),

            new_order_items AS (
                INSERT INTO order_items (
                    order_id, product_id, product_name, unit_price, quantity, subtotal
                )
                SELECT o.id, ci.id, ci.name, ci.price, ci.quantity, ci.subtotal
                FROM new_order o
                CROSS JOIN checked_items ci
                RETURNING id
            )

            SELECT o.*, (SELECT COUNT(*) FROM new_order_items) AS saved_items
            FROM new_order o
        `;

        if (result.length === 0) {
            return bad(res, "Some products are unavailable or out of stock. Please refresh your cart.", 409);
        }

        clearPublicCache("products");

        logOrderEvent(result[0].id, "order_created", null, "pending", `Payment: ${cleanPaymentMethod}`, req.customer ? `customer:${req.customer.id}` : "guest");

        console.log("Order created successfully:", result[0].order_number);

        return res.status(201).json({
            success: true,
            message: isOnline
                ? "Your order has been placed. Payment will be verified by the admin."
                : "Your order has been placed successfully.",
            order_id: result[0].order_number,
            order: result[0]
        });
    } catch (error) {
        console.error("================================");
        console.error("CREATE ORDER ERROR");
        console.error(error);
        console.error("================================");
        return bad(res, "Could not place your order. Please try again.", 500);
    }
});

// =====================================
// ORDER STATE ENGINE (shared by admin and supplier routes)
// =====================================

async function logOrderEvent(orderId, type, oldValue, newValue, note, actor) {
    try {
        await sql`
            INSERT INTO order_events (order_id, event_type, old_value, new_value, note, actor)
            VALUES (${orderId}, ${type}, ${oldValue ?? null}, ${newValue ?? null}, ${note || null}, ${actor || null})
        `;
    } catch (error) {
        console.error("Order event log error:", error.message);
    }
}

/**
 * input: { status, payment_status, delivery_status, tracking_info, delivery_charge, note }
 * returns { error: {code, message} } or { order }
 */
async function applyOrderUpdate(orderId, input, actor) {
    const fail = (code, message) => ({ error: { code, message } });

    const rows = await sql`
        SELECT id, status, payment_status, payment_method, payment_reference,
               delivery_status, tracking_info, delivery_charge
        FROM orders
        WHERE id = ${orderId}
        LIMIT 1
    `;

    if (!rows.length) return fail(404, "Order not found.");

    const cur = rows[0];
    const online = ONLINE_METHODS.includes(cur.payment_method);

    let newStatus = cur.status;
    let newPay = cur.payment_status;
    let newDelivery = cur.delivery_status;

    // ---- order status ----
    if (input.status !== undefined && input.status !== null && input.status !== "") {
        const s = str(input.status).toLowerCase();
        if (!ORDER_STATUSES.includes(s)) return fail(400, "Invalid order status.");
        newStatus = s;
    }

    // ---- delivery status (also moves the order status forward) ----
    if (input.delivery_status !== undefined && input.delivery_status !== null && input.delivery_status !== "") {
        const d = str(input.delivery_status).toLowerCase();
        if (!DELIVERY_STATUSES.includes(d)) return fail(400, "Invalid delivery status.");
        if (cur.status === "cancelled") return fail(409, "A cancelled order cannot be delivered.");
        newDelivery = d;

        const statusStillDefault = newStatus === cur.status;
        if (statusStillDefault) {
            if (d === "order_confirmed" && cur.status === "pending") newStatus = "confirmed";
            else if (["processing", "ready_for_delivery"].includes(d) && ["pending", "confirmed"].includes(cur.status)) newStatus = "processing";
            else if (["shipped", "out_for_delivery"].includes(d) && ["pending", "confirmed", "processing"].includes(cur.status)) newStatus = "shipped";
            else if (d === "delivered") newStatus = "delivered";
        }
    }

    if (newStatus === "delivered") newDelivery = "delivered";
    if (newDelivery === "delivered") newStatus = "delivered";

    if (cur.status === "cancelled" && newStatus !== "cancelled") {
        return fail(409, "A cancelled order cannot be reopened.");
    }
    if (cur.status === "delivered" && newStatus === "cancelled") {
        return fail(409, "A delivered order cannot be cancelled.");
    }

    // ---- payment status ----
    let payTouched = false;

    if (input.payment_status !== undefined && input.payment_status !== null && input.payment_status !== "") {
        let p = str(input.payment_status).toLowerCase();
        p = LEGACY_PAYMENT_MAP[p] || p;

        if (!PAYMENT_STATUSES.includes(p)) return fail(400, "Invalid payment status.");

        if (p !== cur.payment_status) {
            if (p === "paid") {
                if (online) {
                    if (cur.payment_status !== "pending_verification") {
                        return fail(409, "Only a payment waiting for verification can be confirmed.");
                    }
                    if (!cur.payment_reference) {
                        return fail(409, "Payment cannot be confirmed without a Transaction ID.");
                    }
                } else if (newStatus !== "delivered") {
                    return fail(409, "Cash on Delivery can be marked paid only after delivery.");
                }
            } else if (p === "rejected") {
                if (!online || cur.payment_status !== "pending_verification") {
                    return fail(409, "Only a payment waiting for verification can be rejected.");
                }
            } else if (p === "refunded") {
                if (cur.payment_status !== "paid") return fail(409, "Only a paid order can be refunded.");
            } else if (p === "pending_verification") {
                if (!online || !cur.payment_reference) return fail(409, "This order has no Transaction ID to verify.");
            } else if (p === "unpaid") {
                if (["paid", "refunded"].includes(cur.payment_status)) {
                    return fail(409, "A paid or refunded order cannot be set to unpaid.");
                }
            }

            newPay = p;
            payTouched = ["paid", "rejected", "refunded"].includes(p);
        }
    }

    // ---- shipping gate: online orders must be paid first ----
    const shippingNow =
        ["shipped", "delivered"].includes(newStatus) ||
        ["shipped", "out_for_delivery", "delivered"].includes(newDelivery);

    if (online && shippingNow && newPay !== "paid" && cur.payment_status !== "refunded") {
        const movedToShipping =
            newStatus !== cur.status || newDelivery !== cur.delivery_status;
        if (movedToShipping) {
            return fail(409, "Verify and confirm the online payment before shipping this order.");
        }
    }

    // ---- tracking and delivery charge ----
    let tracking = null;
    if (input.tracking_info !== undefined && input.tracking_info !== null) {
        tracking = str(String(input.tracking_info));
        if (tracking.length > 500) return fail(400, "Tracking information is too long.");
    }

    let charge = null;
    if (input.delivery_charge !== undefined && input.delivery_charge !== null && input.delivery_charge !== "") {
        charge = Number(input.delivery_charge);
        if (!Number.isFinite(charge) || charge < 0 || charge > 100000) {
            return fail(400, "Enter a valid delivery charge.");
        }
        charge = Math.round(charge * 100) / 100;
    }

    const note = input.note !== undefined && input.note !== null ? str(String(input.note)).slice(0, 500) : null;

    const statusChanged = newStatus !== cur.status;
    const deliveryChanged = newDelivery !== cur.delivery_status;
    const payChanged = newPay !== cur.payment_status;
    const trackingChanged = tracking !== null && tracking !== (cur.tracking_info || "");
    const chargeChanged = charge !== null && charge !== Number(cur.delivery_charge);

    if (!statusChanged && !deliveryChanged && !payChanged && !trackingChanged && !chargeChanged) {
        const same = await sql`SELECT * FROM orders WHERE id = ${orderId} LIMIT 1`;
        return { order: same[0], unchanged: true };
    }

    // Single statement: update + restock (when cancelled) happen together
    const result = await sql`
        WITH old_order AS (
            SELECT id, status FROM orders WHERE id = ${orderId}
        ),
        updated AS (
            UPDATE orders
            SET
                status = ${newStatus}::text,
                payment_status = ${newPay}::text,
                delivery_status = ${newDelivery}::text,
                tracking_info = COALESCE(${tracking}::text, tracking_info),
                total_amount = CASE
                    WHEN ${charge}::numeric IS NULL THEN total_amount
                    ELSE total_amount - delivery_charge + ${charge}::numeric
                END,
                delivery_charge = COALESCE(${charge}::numeric, delivery_charge),
                delivery_updated_at = CASE
                    WHEN ${deliveryChanged || trackingChanged}::boolean THEN NOW()
                    ELSE delivery_updated_at
                END,
                delivered_at = CASE
                    WHEN ${newDelivery}::text = 'delivered' AND delivered_at IS NULL THEN NOW()
                    ELSE delivered_at
                END,
                payment_verified_at = CASE
                    WHEN ${payTouched}::boolean THEN NOW() ELSE payment_verified_at
                END,
                payment_verified_by = CASE
                    WHEN ${payTouched}::boolean THEN ${actor}::text ELSE payment_verified_by
                END,
                payment_note = COALESCE(${payTouched ? note : null}::text, payment_note)
            WHERE id = ${orderId}
            RETURNING *
        ),
        restock AS (
            UPDATE products p
            SET stock_quantity = p.stock_quantity + oi.quantity,
                updated_at = NOW()
            FROM order_items oi, old_order o
            WHERE oi.order_id = ${orderId}
              AND p.id = oi.product_id
              AND ${newStatus}::text = 'cancelled'
              AND o.status <> 'cancelled'
            RETURNING p.id
        )
        SELECT * FROM updated
    `;

    if (!result.length) return fail(404, "Order not found.");

    if (statusChanged) await logOrderEvent(orderId, "status", cur.status, newStatus, note, actor);
    if (deliveryChanged) await logOrderEvent(orderId, "delivery_status", cur.delivery_status, newDelivery, note, actor);
    if (payChanged) await logOrderEvent(orderId, "payment_status", cur.payment_status, newPay, note, actor);
    if (trackingChanged) await logOrderEvent(orderId, "tracking", cur.tracking_info, tracking, null, actor);
    if (chargeChanged) await logOrderEvent(orderId, "delivery_charge", String(cur.delivery_charge), String(charge), null, actor);

    if (newStatus === "cancelled" && statusChanged) clearPublicCache("products");

    return { order: result[0] };
}

// =====================================
// ADMIN LOGIN
// =====================================

app.post("/api/admin/login", adminLoginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body || {};

        if (
            typeof email !== "string" || typeof password !== "string" ||
            !email.trim() || !password || email.length > 255 || password.length > 128
        ) {
            return bad(res, "Email and password are required.");
        }

        const normalizedEmail = email.trim().toLowerCase();

        const admins = await sql`
            SELECT id, name, email, password_hash, role, is_active
            FROM admins
            WHERE LOWER(email) = ${normalizedEmail}
            LIMIT 1
        `;

        const admin = admins[0];

        const passwordMatches = await bcrypt.compare(
            password,
            admin ? admin.password_hash : DUMMY_PASSWORD_HASH
        );

        if (!admin || !admin.is_active || !passwordMatches) {
            return bad(res, "Invalid email or password.", 401);
        }

        const token = jwt.sign(
            { role: admin.role, type: "admin" },
            JWT_SECRET,
            { subject: String(admin.id), expiresIn: "8h", algorithm: "HS256" }
        );

        setAdminCookie(res, token);
        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            message: "Admin login successful.",
            admin: { id: admin.id, name: admin.name, email: admin.email, role: admin.role }
        });
    } catch (error) {
        console.error("Admin login error:", error);
        return bad(res, "Login failed due to a server error.", 500);
    }
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.json({ success: true, admin: req.admin });
});

app.post("/api/admin/logout", (req, res) => {
    clearAdminCookie(res);
    res.setHeader("Cache-Control", "no-store");
    res.json({ success: true, message: "Logged out successfully." });
});

// =====================================
// DASHBOARD STATISTICS
// =====================================

app.get("/api/admin/dashboard-stats", requireAdmin, async (req, res) => {
    try {
        const result = await sql`
            SELECT
                (SELECT COUNT(*) FROM products WHERE is_active = TRUE) AS total_products,
                (SELECT COUNT(*) FROM orders WHERE is_archived = FALSE) AS total_orders,
                (SELECT COUNT(*) FROM customers WHERE is_archived = FALSE) AS total_customers,
                (SELECT COUNT(*) FROM messages) AS total_messages,
                (SELECT COUNT(*) FROM messages WHERE status = 'unread') AS unread_messages,
                (SELECT COUNT(*) FROM orders WHERE is_archived = FALSE AND status = 'pending') AS pending_orders,
                (SELECT COUNT(*) FROM orders WHERE is_archived = FALSE AND payment_status = 'pending_verification') AS payments_to_verify,
                (SELECT COUNT(*) FROM products WHERE is_active = TRUE AND stock_quantity <= 0) AS out_of_stock
        `;

        const s = result[0];
        res.setHeader("Cache-Control", "no-store");

        res.json({
            success: true,
            statistics: {
                totalProducts: Number(s.total_products),
                totalOrders: Number(s.total_orders),
                totalCustomers: Number(s.total_customers),
                totalMessages: Number(s.total_messages),
                unreadMessages: Number(s.unread_messages),
                pendingOrders: Number(s.pending_orders),
                paymentsToVerify: Number(s.payments_to_verify),
                outOfStock: Number(s.out_of_stock)
            }
        });
    } catch (error) {
        console.error("Dashboard statistics error:", error);
        bad(res, "Could not load dashboard statistics.", 500);
    }
});

// =====================================
// ADMIN SETTINGS (payment numbers, delivery charge, support links)
// =====================================

app.get("/api/admin/settings", requireAdmin, async (req, res) => {
    try {
        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, settings: await getSettings(true) });
    } catch (error) {
        console.error("Load settings error:", error);
        bad(res, "Could not load settings.", 500);
    }
});

app.put("/api/admin/settings", requireAdmin, async (req, res) => {
    try {
        const body = req.body || {};
        const updates = {};

        if (body.delivery_charge !== undefined) {
            const n = Number(body.delivery_charge);
            if (!Number.isFinite(n) || n < 0 || n > 100000) return bad(res, "Enter a valid delivery charge.");
            updates.delivery_charge = String(Math.round(n * 100) / 100);
        }

        for (const key of ["bkash_number", "nagad_number"]) {
            if (body[key] !== undefined) {
                const v = str(body[key]);
                if (v && !/^[0-9+\-\s]{6,20}$/.test(v)) return bad(res, `Invalid ${key.replace("_", " ")}.`);
                updates[key] = v;
            }
        }

        if (body.whatsapp_number !== undefined) {
            const v = str(body.whatsapp_number).replace(/[\s+\-]/g, "");
            if (v && !/^\d{8,15}$/.test(v)) return bad(res, "Invalid WhatsApp number (use country code, digits only).");
            updates.whatsapp_number = v;
        }

        if (body.facebook_url !== undefined) {
            const v = str(body.facebook_url);
            if (v) {
                let parsed;
                try { parsed = new URL(v); } catch { return bad(res, "Invalid Facebook link."); }
                if (parsed.protocol !== "https:" || v.length > 300) return bad(res, "Facebook link must start with https://");
            }
            updates.facebook_url = v;
        }

        if (!Object.keys(updates).length) return bad(res, "Nothing to update.");

        await sql`
            INSERT INTO app_settings (key, value, updated_at)
            SELECT key, value, NOW() FROM jsonb_each_text(${JSON.stringify(updates)}::jsonb)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        `;

        clearPublicCache("settings");

        res.json({ success: true, message: "Settings saved.", settings: await getSettings(true) });
    } catch (error) {
        console.error("Save settings error:", error);
        bad(res, "Could not save settings.", 500);
    }
});

// =====================================
// ADMIN PRODUCT IMAGE UPLOAD
// =====================================

app.post(
    "/api/admin/products/upload-image",
    requireAdmin,
    imageUploadLimiter,
    (req, res, next) => {
        imageUpload.single("image")(req, res, error => {
            if (error) {
                const message = error.code === "LIMIT_FILE_SIZE"
                    ? "Image must be 5MB or smaller."
                    : error.message || "Image upload failed.";
                return bad(res, message);
            }
            next();
        });
    },
    async (req, res) => {
        try {
            if (!req.file) return bad(res, "Please select an image.");

            const { fileTypeFromBuffer } = await import("file-type");
            const detected = await fileTypeFromBuffer(req.file.buffer);

            if (!detected || !allowedImageTypes[detected.mime]) {
                return bad(res, "Invalid image file. Please select a real JPG, PNG, WEBP or GIF image.");
            }

            const filename = crypto.randomBytes(20).toString("hex") + "." + allowedImageTypes[detected.mime];
            await fs.promises.writeFile(path.join(uploadDirectory, filename), req.file.buffer, { flag: "wx" });

            return res.status(201).json({
                success: true,
                message: "Image uploaded successfully.",
                image_url: `/uploads/${filename}`
            });
        } catch (error) {
            console.error("Product image upload error:", error);
            return bad(res, "Could not upload image.", 500);
        }
    }
);

// =====================================
// ADMIN SUPPLIER MANAGEMENT
// =====================================

function readSupplierBody(body) {
    return {
        name: str(body.supplier_name),
        business: str(body.business_name),
        phone: str(body.phone),
        whatsapp: str(body.whatsapp),
        address: str(body.address),
        district: str(body.district),
        notes: str(body.notes)
    };
}

function supplierFieldsTooLong(s) {
    return s.business.length > 180 || s.phone.length > 30 || s.whatsapp.length > 30 ||
        s.address.length > 5000 || s.district.length > 100 || s.notes.length > 5000;
}

app.get("/api/admin/suppliers", requireAdmin, async (req, res) => {
    try {
        const suppliers = await sql`
            SELECT id, supplier_name, business_name, phone, whatsapp, address,
                   district, status, notes, created_at, updated_at
            FROM suppliers
            ORDER BY id DESC
        `;
        res.setHeader("Cache-Control", "no-store");
        return res.json({ success: true, suppliers });
    } catch (error) {
        console.error("Load suppliers error:", error);
        return bad(res, "Could not load suppliers.", 500);
    }
});

app.post("/api/admin/suppliers", requireAdmin, async (req, res) => {
    try {
        const s = readSupplierBody(req.body || {});
        const status = (req.body || {}).status || "active";

        if (!s.name || s.name.length > 150) return bad(res, "Supplier name is required (maximum 150 characters).");
        if (supplierFieldsTooLong(s)) return bad(res, "One or more fields exceed the allowed length.");
        if (!["active", "inactive"].includes(status)) return bad(res, "Invalid supplier status.");

        const result = await sql`
            INSERT INTO suppliers (supplier_name, business_name, phone, whatsapp, address, district, status, notes)
            VALUES (
                ${s.name}, ${s.business || null}, ${s.phone || null}, ${s.whatsapp || null},
                ${s.address || null}, ${s.district || null}, ${status}, ${s.notes || null}
            )
            RETURNING *
        `;

        res.setHeader("Cache-Control", "no-store");
        return res.status(201).json({ success: true, message: "Supplier added successfully.", supplier: result[0] });
    } catch (error) {
        console.error("Add supplier error:", error);
        return bad(res, "Could not add supplier.", 500);
    }
});

app.put("/api/admin/suppliers/:id", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidId(id)) return bad(res, "Invalid supplier ID.");

        const s = readSupplierBody(req.body || {});
        const status = (req.body || {}).status;

        if (!s.name || s.name.length > 150) return bad(res, "Supplier name is required.");
        if (supplierFieldsTooLong(s)) return bad(res, "One or more fields exceed the allowed length.");
        if (!["active", "inactive"].includes(status)) return bad(res, "Invalid supplier status.");

        const result = await sql`
            UPDATE suppliers
            SET supplier_name = ${s.name},
                business_name = ${s.business || null},
                phone = ${s.phone || null},
                whatsapp = ${s.whatsapp || null},
                address = ${s.address || null},
                district = ${s.district || null},
                status = ${status},
                notes = ${s.notes || null},
                updated_at = NOW()
            WHERE id = ${id}
            RETURNING *
        `;

        if (!result.length) return bad(res, "Supplier not found.", 404);

        res.setHeader("Cache-Control", "no-store");
        return res.json({ success: true, message: "Supplier updated successfully.", supplier: result[0] });
    } catch (error) {
        console.error("Update supplier error:", error);
        return bad(res, "Could not update supplier.", 500);
    }
});

app.delete("/api/admin/suppliers/:id", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidId(id)) return bad(res, "Invalid supplier ID.");

        const result = await sql`
            UPDATE suppliers SET status = 'inactive', updated_at = NOW()
            WHERE id = ${id}
            RETURNING id
        `;

        if (!result.length) return bad(res, "Supplier not found.", 404);
        return res.json({ success: true, message: "Supplier deactivated successfully." });
    } catch (error) {
        console.error("Deactivate supplier error:", error);
        return bad(res, "Could not deactivate supplier.", 500);
    }
});

// =====================================
// ADMIN CATEGORIES
// =====================================

app.get("/api/admin/categories", requireAdmin, async (req, res) => {
    try {
        const categories = await sql`
            SELECT c.id, c.name, c.is_active, c.created_at,
                   (SELECT COUNT(*) FROM products p
                    WHERE p.is_active = TRUE AND LOWER(p.category) = LOWER(c.name)) AS product_count
            FROM categories c
            ORDER BY c.name ASC
        `;
        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, categories });
    } catch (error) {
        console.error("Load categories error:", error);
        bad(res, "Could not load categories.", 500);
    }
});

app.post("/api/admin/categories", requireAdmin, async (req, res) => {
    try {
        const name = str((req.body || {}).name);
        if (!name || name.length > 100) return bad(res, "Enter a valid category name (maximum 100 characters).");

        const result = await sql`
            INSERT INTO categories (name) VALUES (${name})
            RETURNING id, name, is_active, created_at
        `;

        clearPublicCache("categories");
        res.status(201).json({ success: true, message: "Category added successfully.", category: result[0] });
    } catch (error) {
        if (error && error.code === "23505") return bad(res, "This category already exists.", 409);
        console.error("Add category error:", error);
        bad(res, "Could not add category.", 500);
    }
});

app.put("/api/admin/categories/:id", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidId(id)) return bad(res, "Invalid category ID.");

        const name = str((req.body || {}).name);
        const isActive = (req.body || {}).is_active;

        if (!name || name.length > 100) return bad(res, "Enter a valid category name.");
        if (isActive !== undefined && typeof isActive !== "boolean") return bad(res, "Invalid category status.");

        // rename the category and every product that uses it in one statement
        const result = await sql`
            WITH old_cat AS (
                SELECT id, name FROM categories WHERE id = ${id}
            ),
            updated AS (
                UPDATE categories
                SET name = ${name},
                    is_active = COALESCE(${isActive ?? null}::boolean, is_active)
                WHERE id = ${id}
                RETURNING id, name, is_active
            ),
            moved AS (
                UPDATE products p
                SET category = ${name}
                FROM old_cat o
                WHERE LOWER(p.category) = LOWER(o.name)
                RETURNING p.id
            )
            SELECT * FROM updated
        `;

        if (!result.length) return bad(res, "Category not found.", 404);

        clearPublicCache("categories");
        clearPublicCache("products");
        res.json({ success: true, message: "Category updated successfully.", category: result[0] });
    } catch (error) {
        if (error && error.code === "23505") return bad(res, "This category already exists.", 409);
        console.error("Update category error:", error);
        bad(res, "Could not update category.", 500);
    }
});

app.delete("/api/admin/categories/:id", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidId(id)) return bad(res, "Invalid category ID.");

        const result = await sql`
            WITH removed AS (
                DELETE FROM categories WHERE id = ${id} RETURNING id, name
            ),
            cleared AS (
                UPDATE products p SET category = NULL
                FROM removed r
                WHERE LOWER(p.category) = LOWER(r.name)
                RETURNING p.id
            )
            SELECT id FROM removed
        `;

        if (!result.length) return bad(res, "Category not found.", 404);

        clearPublicCache("categories");
        clearPublicCache("products");
        res.json({ success: true, message: "Category deleted. Its products now have no category." });
    } catch (error) {
        console.error("Delete category error:", error);
        bad(res, "Could not delete category.", 500);
    }
});

// =====================================
// ADMIN PRODUCTS
// =====================================

const MAX_PRICE = 9999999999;
const MAX_STOCK = 2147483647;

function validImageValue(image) {
    return !image ||
        /^https?:\/\//i.test(image) ||
        /^\/uploads\/[a-f0-9]{40}\.(jpg|png|webp|gif)$/i.test(image);
}

async function ensureCategory(name) {
    if (!name) return;
    try {
        await sql`INSERT INTO categories (name) VALUES (${name}) ON CONFLICT DO NOTHING`;
        clearPublicCache("categories");
    } catch (error) {
        console.error("Ensure category error:", error.message);
    }
}

app.get("/api/admin/products", requireAdmin, async (req, res) => {
    try {
        const products = await sql`
            SELECT id, name, description, price, stock_quantity, image_url, is_active,
                   discount_percent, discount_enabled, category, created_at, updated_at
            FROM products
            WHERE is_active = TRUE
            ORDER BY id DESC
        `;
        res.setHeader("Cache-Control", "no-store");
        return res.json({ success: true, products });
    } catch (error) {
        console.error("Load products error:", error);
        return bad(res, "Could not load products.", 500);
    }
});

app.post("/api/admin/products", requireAdmin, async (req, res) => {
    try {
        const { name, description, price, stock_quantity, image_url, discount_percent, discount_enabled, category } = req.body || {};

        const cleanName = str(name);
        const cleanDescription = str(description);
        const cleanImage = str(image_url);
        const cleanCategory = str(category);
        const numericPrice = Number(price);
        const numericStock = Number(stock_quantity ?? 0);
        const numericDiscount = Number(discount_percent ?? 0);
        const cleanDiscountEnabled = discount_enabled ?? false;

        if (!cleanName || cleanName.length > 200) return bad(res, "Product name is required.");
        if (price === undefined || price === null || price === "" || !Number.isFinite(numericPrice) ||
            numericPrice < 0 || numericPrice > MAX_PRICE) return bad(res, "Enter a valid product price.");
        if (!Number.isSafeInteger(numericStock) || numericStock < 0 || numericStock > MAX_STOCK) {
            return bad(res, "Invalid stock quantity.");
        }
        if (!Number.isFinite(numericDiscount) || numericDiscount < 0 || numericDiscount > 99.99) {
            return bad(res, "Discount must be between 0 and 99.99 percent.");
        }
        if (typeof cleanDiscountEnabled !== "boolean") return bad(res, "Invalid discount status.");
        if (cleanCategory.length > 100) return bad(res, "Category name is too long.");
        if (!validImageValue(cleanImage)) return bad(res, "Invalid image URL.");

        const result = await sql`
            INSERT INTO products (
                name, description, price, stock_quantity, image_url, is_active,
                discount_percent, discount_enabled, category
            )
            VALUES (
                ${cleanName}, ${cleanDescription}, ${numericPrice}, ${numericStock},
                ${cleanImage || null}, TRUE, ${numericDiscount}, ${cleanDiscountEnabled},
                ${cleanCategory || null}
            )
            RETURNING *
        `;

        await ensureCategory(cleanCategory);
        clearPublicCache("products");

        return res.status(201).json({ success: true, message: "Product added successfully.", product: result[0] });
    } catch (error) {
        console.error("Add product error:", error);
        return bad(res, "Could not add product.", 500);
    }
});

app.put("/api/admin/products/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid product ID.");

        const { name, description, price, stock_quantity, image_url, discount_percent, discount_enabled, category } = req.body || {};

        const cleanName = str(name);
        const cleanDescription = str(description);
        const cleanImage = str(image_url);
        const numericPrice = Number(price);
        const numericStock = Number(stock_quantity ?? 0);

        let numericDiscount = null;
        if (discount_percent !== undefined) {
            numericDiscount = Number(discount_percent);
            if (!Number.isFinite(numericDiscount) || numericDiscount < 0 || numericDiscount > 99.99) {
                return bad(res, "Discount must be between 0 and 99.99 percent.");
            }
        }

        let cleanDiscountEnabled = null;
        if (discount_enabled !== undefined) {
            if (typeof discount_enabled !== "boolean") return bad(res, "Invalid discount status.");
            cleanDiscountEnabled = discount_enabled;
        }

        // category: undefined = keep, "" = clear, text = set
        let categoryProvided = category !== undefined;
        const cleanCategory = categoryProvided ? str(category) : "";
        if (cleanCategory.length > 100) return bad(res, "Category name is too long.");

        if (!cleanName || cleanName.length > 200) return bad(res, "Product name is required.");
        if (price === undefined || price === null || price === "" || !Number.isFinite(numericPrice) ||
            numericPrice < 0 || numericPrice > MAX_PRICE) return bad(res, "Enter a valid product price.");
        if (!Number.isSafeInteger(numericStock) || numericStock < 0 || numericStock > MAX_STOCK) {
            return bad(res, "Invalid stock quantity.");
        }
        if (!validImageValue(cleanImage)) return bad(res, "Invalid image URL.");

        const result = await sql`
            UPDATE products
            SET name = ${cleanName},
                description = ${cleanDescription},
                price = ${numericPrice},
                stock_quantity = ${numericStock},
                image_url = ${cleanImage || null},
                discount_percent = COALESCE(${numericDiscount}, discount_percent),
                discount_enabled = COALESCE(${cleanDiscountEnabled}, discount_enabled),
                category = CASE WHEN ${categoryProvided}::boolean THEN ${cleanCategory || null}::text ELSE category END,
                updated_at = NOW()
            WHERE id = ${id} AND is_active = TRUE
            RETURNING *
        `;

        if (!result.length) return bad(res, "Product not found.", 404);

        if (categoryProvided) await ensureCategory(cleanCategory);
        clearPublicCache("products");

        return res.json({ success: true, message: "Product updated successfully.", product: result[0] });
    } catch (error) {
        console.error("Update product error:", error);
        return bad(res, "Could not update product.", 500);
    }
});

app.delete("/api/admin/products/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid product ID.");

        const result = await sql`
            WITH deactivated_product AS (
                UPDATE products SET is_active = FALSE, updated_at = NOW()
                WHERE id = ${id}
                RETURNING id
            ),
            hidden_supplier_links AS (
                UPDATE supplier_products
                SET approval_status = 'rejected',
                    admin_approval_note = 'Deleted by Admin',
                    updated_at = NOW()
                WHERE product_id IN (SELECT id FROM deactivated_product)
                  AND COALESCE(admin_approval_note, '') NOT IN (
                      'Deleted by Admin', 'Deleted by Supplier', 'Deactivated by Admin'
                  )
                RETURNING id
            )
            SELECT id FROM deactivated_product
        `;

        if (!result.length) return bad(res, "Product not found.", 404);

        clearPublicCache("products");
        return res.json({ success: true, message: "Product and its supplier links deactivated successfully." });
    } catch (error) {
        console.error("Delete product error:", error);
        return bad(res, "Could not deactivate product and its supplier links.", 500);
    }
});

// =====================================
// ADMIN SERVICES MANAGEMENT
// =====================================

const SLUG_REGEX = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

app.get("/api/admin/services", requireAdmin, async (req, res) => {
    try {
        const services = await sql`
            SELECT id, title, slug, description, is_active, created_at
            FROM services
            ORDER BY id DESC
        `;
        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, services });
    } catch (error) {
        console.error("Load services error:", error);
        bad(res, "Could not load services.", 500);
    }
});

app.post("/api/admin/services", requireAdmin, async (req, res) => {
    try {
        const { title, slug, description, is_active } = req.body || {};
        const cleanTitle = str(title);
        const cleanSlug = str(slug).toLowerCase();
        const cleanDescription = str(description);

        if (!cleanTitle || cleanTitle.length > 200) return bad(res, "Enter a valid service title.");
        if (!cleanSlug || cleanSlug.length > 200 || !SLUG_REGEX.test(cleanSlug)) {
            return bad(res, "Enter a valid slug using lowercase letters, numbers and hyphens.");
        }

        const result = await sql`
            INSERT INTO services (title, slug, description, is_active)
            VALUES (${cleanTitle}, ${cleanSlug}, ${cleanDescription}, ${is_active !== false})
            RETURNING *
        `;

        clearPublicCache("services");
        res.status(201).json({ success: true, message: "Service added successfully.", service: result[0] });
    } catch (error) {
        console.error("Add service error:", error);
        bad(res, "Could not add service. Check whether the slug already exists.", 500);
    }
});

app.put("/api/admin/services/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid service ID.");

        const { title, slug, description, is_active } = req.body || {};
        const cleanTitle = str(title);
        const cleanSlug = str(slug).toLowerCase();
        const cleanDescription = str(description);

        if (!cleanTitle || cleanTitle.length > 200) return bad(res, "Enter a valid service title.");
        if (!cleanSlug || cleanSlug.length > 200 || !SLUG_REGEX.test(cleanSlug)) return bad(res, "Enter a valid slug.");
        if (typeof is_active !== "boolean") return bad(res, "Invalid service status.");

        const result = await sql`
            UPDATE services
            SET title = ${cleanTitle}, slug = ${cleanSlug},
                description = ${cleanDescription}, is_active = ${is_active}
            WHERE id = ${id}
            RETURNING *
        `;

        if (!result.length) return bad(res, "Service not found.", 404);

        clearPublicCache("services");
        res.json({ success: true, message: "Service updated successfully.", service: result[0] });
    } catch (error) {
        console.error("Update service error:", error);
        bad(res, "Could not update service. Check whether the slug already exists.", 500);
    }
});

app.delete("/api/admin/services/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid service ID.");

        const result = await sql`DELETE FROM services WHERE id = ${id} RETURNING id`;
        if (!result.length) return bad(res, "Service not found.", 404);

        clearPublicCache("services");
        res.json({ success: true, message: "Service deleted successfully." });
    } catch (error) {
        console.error("Delete service error:", error);
        bad(res, "Could not delete service.", 500);
    }
});

// =====================================
// ADMIN ORDERS
// =====================================

app.get("/api/admin/orders", requireAdmin, async (req, res) => {
    try {
        const showArchived = req.query.archived === "true";

        const orders = await sql`
            SELECT
                o.id, o.customer_id, o.order_number, o.total_amount, o.delivery_charge,
                o.status, o.payment_status, o.payment_method, o.payment_reference,
                o.payment_verified_at, o.payment_verified_by, o.payment_note,
                o.delivery_status, o.tracking_info, o.delivered_at, o.delivery_updated_at,
                o.delivery_address, o.created_at, o.is_archived,
                COALESCE(o.delivery_name, c.name) AS customer_name,
                COALESCE(o.delivery_phone, c.phone) AS customer_phone,
                c.email AS customer_email
            FROM orders o
            LEFT JOIN customers c ON c.id = o.customer_id
            WHERE o.is_archived = ${showArchived}
            ORDER BY o.id DESC
        `;

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, orders });
    } catch (error) {
        console.error("Load orders error:", error);
        bad(res, "Could not load orders.", 500);
    }
});

app.get("/api/admin/orders/:id/items", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid order ID.");

        const items = await sql`
            SELECT id, product_id, product_name, unit_price, quantity, subtotal
            FROM order_items
            WHERE order_id = ${id}
            ORDER BY id ASC
        `;

        res.setHeader("Cache-Control", "no-store");
        return res.json({ success: true, items });
    } catch (error) {
        console.error("Load order items error:", error);
        return bad(res, "Could not load order items.", 500);
    }
});

app.get("/api/admin/orders/:id/events", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid order ID.");

        const events = await sql`
            SELECT id, event_type, old_value, new_value, note, actor, created_at
            FROM order_events
            WHERE order_id = ${id}
            ORDER BY id ASC
        `;

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, events });
    } catch (error) {
        console.error("Load order events error:", error);
        bad(res, "Could not load order history.", 500);
    }
});

// Order status, payment status, delivery status, tracking and delivery charge.
// /status is kept (old admin pages use it); /delivery is an alias.
app.put(["/api/admin/orders/:id/status", "/api/admin/orders/:id/delivery"], requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid order ID.");

        const b = req.body || {};
        const hasAnything = ["status", "payment_status", "delivery_status", "tracking_info", "delivery_charge"]
            .some(k => b[k] !== undefined && b[k] !== null && b[k] !== "");

        if (!hasAnything) return bad(res, "Provide at least one field to update.");

        const outcome = await applyOrderUpdate(id, b, `admin:${req.admin.name || req.admin.id}`);
        if (outcome.error) return bad(res, outcome.error.message, outcome.error.code);

        res.json({ success: true, message: "Order updated successfully.", order: outcome.order });
    } catch (error) {
        console.error("Update order error:", error);
        bad(res, "Could not update order.", 500);
    }
});

// Verify a Transaction ID: confirm, reject or refund
app.put("/api/admin/orders/:id/payment", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid order ID.");

        const action = str((req.body || {}).action).toLowerCase();
        const map = { confirm: "paid", reject: "rejected", refund: "refunded" };

        if (!map[action]) return bad(res, "Action must be confirm, reject or refund.");

        const outcome = await applyOrderUpdate(
            id,
            { payment_status: map[action], note: (req.body || {}).note },
            `admin:${req.admin.name || req.admin.id}`
        );

        if (outcome.error) return bad(res, outcome.error.message, outcome.error.code);

        res.json({ success: true, message: `Payment ${action === "confirm" ? "confirmed" : action === "reject" ? "rejected" : "refunded"}.`, order: outcome.order });
    } catch (error) {
        console.error("Payment verification error:", error);
        bad(res, "Could not update payment.", 500);
    }
});

app.patch("/api/admin/orders/:id/archive", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid order ID.");

        const result = await sql`
            UPDATE orders SET is_archived = TRUE
            WHERE id = ${id} AND is_archived = FALSE
            RETURNING id
        `;

        if (!result.length) return bad(res, "Active order not found.", 404);
        res.json({ success: true, message: "Order archived successfully." });
    } catch (error) {
        console.error("Archive order error:", error);
        bad(res, "Could not archive order.", 500);
    }
});

app.patch("/api/admin/orders/:id/restore", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid order ID.");

        const result = await sql`
            UPDATE orders SET is_archived = FALSE
            WHERE id = ${id} AND is_archived = TRUE
            RETURNING id
        `;

        if (!result.length) return bad(res, "Archived order not found.", 404);
        res.json({ success: true, message: "Order restored successfully." });
    } catch (error) {
        console.error("Restore order error:", error);
        bad(res, "Could not restore order.", 500);
    }
});

app.delete("/api/admin/orders/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid order ID.");

        const existing = await sql`
            SELECT id FROM orders WHERE id = ${id} AND is_archived = TRUE LIMIT 1
        `;
        if (!existing.length) return bad(res, "Only archived orders can be permanently deleted.");

        const deleted = await sql`
            WITH deleted_items AS (
                DELETE FROM order_items WHERE order_id = ${id} RETURNING id
            ),
            deleted_events AS (
                DELETE FROM order_events WHERE order_id = ${id} RETURNING id
            ),
            deleted_order AS (
                DELETE FROM orders WHERE id = ${id} AND is_archived = TRUE RETURNING id
            )
            SELECT id FROM deleted_order
        `;

        if (!deleted.length) return bad(res, "Order not found.", 404);
        res.json({ success: true, message: "Order permanently deleted." });
    } catch (error) {
        console.error("Permanent delete order error:", error);
        bad(res, "Could not permanently delete order.", 500);
    }
});

// =====================================
// ADMIN CUSTOMERS
// =====================================

app.get("/api/admin/customers", requireAdmin, async (req, res) => {
    try {
        const showArchived = req.query.archived === "true";

        const customers = await sql`
            SELECT c.id, c.name, c.email, c.phone, c.address, c.created_at, c.is_archived,
                   (c.password_hash IS NOT NULL) AS has_account,
                   c.last_login_at,
                   (SELECT COUNT(*) FROM orders o WHERE o.customer_id = c.id) AS order_count
            FROM customers c
            WHERE c.is_archived = ${showArchived}
            ORDER BY c.id DESC
        `;

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, customers });
    } catch (error) {
        console.error("Load customers error:", error);
        bad(res, "Could not load customers.", 500);
    }
});

// must stay above /customers/:id
app.get("/api/admin/customers/export.csv", requireAdmin, async (req, res) => {
    try {
        const showArchived = req.query.archived === "true";

        const customers = await sql`
            SELECT id, name, email, phone, created_at, is_archived
            FROM customers
            WHERE is_archived = ${showArchived}
            ORDER BY id DESC
        `;

        const csvCell = value => {
            let text = value == null ? "" : String(value);
            if (/^\s*[=+\-@\t\r]/.test(text)) text = "'" + text;
            return `"${text.replace(/"/g, '""')}"`;
        };

        const rows = [
            ["ID", "Name", "Email", "Phone", "Created At", "Archived"],
            ...customers.map(c => [c.id, c.name, c.email, c.phone, c.created_at, c.is_archived ? "Yes" : "No"])
        ];

        const csv = "\uFEFF" + rows.map(row => row.map(csvCell).join(",")).join("\r\n");

        res.setHeader("Cache-Control", "no-store");
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="customers-${showArchived ? "archived" : "active"}.csv"`);
        res.send(csv);
    } catch (error) {
        console.error("Export customers error:", error);
        bad(res, "Could not export customers.", 500);
    }
});

app.get("/api/admin/customers/:id", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidId(id)) return bad(res, "Invalid customer ID.");

        const result = await sql`
            SELECT id, name, email, phone, address, created_at, is_archived,
                   (password_hash IS NOT NULL) AS has_account, last_login_at
            FROM customers
            WHERE id = ${id}
            LIMIT 1
        `;

        if (!result.length) return bad(res, "Customer not found.", 404);

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, customer: result[0] });
    } catch (error) {
        console.error("Customer details error:", error);
        bad(res, "Could not load customer details.", 500);
    }
});

app.put("/api/admin/customers/:id", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidId(id)) return bad(res, "Invalid customer ID.");

        const body = req.body || {};
        const name = str(body.name);
        const emailInput = str(body.email).toLowerCase();
        const phoneInput = normalizePhone(body.phone);
        const addressInput = typeof body.address === "string" ? body.address.trim() : null;

        if (!name || name.length > 150) return bad(res, "Name is required and must be within 150 characters.");
        if (emailInput.length > 255 || (emailInput && !EMAIL_REGEX.test(emailInput))) {
            return bad(res, "Please enter a valid email address.");
        }
        if (phoneInput.length > 30) return bad(res, "Phone number is too long.");
        if (addressInput && addressInput.length > 1000) return bad(res, "Address is too long.");

        const email = emailInput || null;
        const phone = phoneInput || null;

        if (email) {
            const duplicate = await sql`
                SELECT id FROM customers
                WHERE LOWER(email) = LOWER(${email}) AND id <> ${id}
                LIMIT 1
            `;
            if (duplicate.length) return bad(res, "This email is already used by another customer.", 409);
        }

        const updated = await sql`
            UPDATE customers
            SET name = ${name},
                email = ${email},
                phone = ${phone},
                address = COALESCE(${addressInput}::text, address)
            WHERE id = ${id}
            RETURNING id, name, email, phone, address, created_at, is_archived
        `;

        if (!updated.length) return bad(res, "Customer not found.", 404);

        res.json({ success: true, message: "Customer updated successfully.", customer: updated[0] });
    } catch (error) {
        console.error("Update customer error:", error);
        bad(res, "Could not update customer.", 500);
    }
});

app.get("/api/admin/customers/:id/orders", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidId(id)) return bad(res, "Invalid customer ID.");

        const customer = await sql`SELECT id FROM customers WHERE id = ${id} LIMIT 1`;
        if (!customer.length) return bad(res, "Customer not found.", 404);

        const orders = await sql`
            SELECT id, customer_id, order_number, total_amount, delivery_charge,
                   status, payment_status, payment_method, payment_reference,
                   delivery_status, tracking_info, delivery_address,
                   created_at, is_archived
            FROM orders
            WHERE customer_id = ${id}
            ORDER BY id DESC
        `;

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, orders });
    } catch (error) {
        console.error("Customer orders error:", error);
        bad(res, "Could not load customer orders.", 500);
    }
});

app.patch("/api/admin/customers/:id/archive", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidId(id)) return bad(res, "Invalid customer ID.");

        // raising token_version also logs the customer out everywhere
        const result = await sql`
            UPDATE customers
            SET is_archived = TRUE, token_version = token_version + 1
            WHERE id = ${id} AND is_archived = FALSE
            RETURNING id
        `;

        if (!result.length) return bad(res, "Active customer not found.", 404);
        res.json({ success: true, message: "Customer archived successfully." });
    } catch (error) {
        console.error("Archive customer error:", error);
        bad(res, "Could not archive customer.", 500);
    }
});

app.patch("/api/admin/customers/:id/restore", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidId(id)) return bad(res, "Invalid customer ID.");

        const result = await sql`
            UPDATE customers SET is_archived = FALSE
            WHERE id = ${id} AND is_archived = TRUE
            RETURNING id
        `;

        if (!result.length) return bad(res, "Archived customer not found.", 404);
        res.json({ success: true, message: "Customer restored successfully." });
    } catch (error) {
        console.error("Restore customer error:", error);
        bad(res, "Could not restore customer.", 500);
    }
});

app.delete("/api/admin/customers/:id", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidId(id)) return bad(res, "Invalid customer ID.");

        const customer = await sql`
            SELECT id, is_archived FROM customers WHERE id = ${id} LIMIT 1
        `;

        if (!customer.length) return bad(res, "Customer not found.", 404);
        if (!customer[0].is_archived) return bad(res, "Archive the customer before permanently deleting.");

        const orderCount = await sql`
            SELECT COUNT(*) AS total FROM orders WHERE customer_id = ${id}
        `;

        if (Number(orderCount[0].total) > 0) {
            return bad(res, "This customer has orders. Archive the customer instead to preserve order history.", 409);
        }

        await sql`DELETE FROM customers WHERE id = ${id} AND is_archived = TRUE`;
        res.json({ success: true, message: "Customer permanently deleted." });
    } catch (error) {
        console.error("Delete customer error:", error);
        if (error && error.code === "23503") {
            return bad(res, "Could not delete customer. Related records exist.", 409);
        }
        bad(res, "Could not delete customer.", 500);
    }
});

// =====================================
// ADMIN MESSAGES (customer support)
// =====================================

app.get("/api/admin/messages", requireAdmin, async (req, res) => {
    try {
        const messages = await sql`
            SELECT id, name, phone, email, subject, message, status,
                   customer_id, order_id, admin_reply, replied_at, created_at
            FROM messages
            ORDER BY id DESC
        `;
        res.setHeader("Cache-Control", "no-store");
        return res.json({ success: true, messages });
    } catch (error) {
        console.error("Load messages error:", error);
        return bad(res, "Could not load messages.", 500);
    }
});

app.get("/api/admin/messages/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid message ID.");

        const result = await sql`
            SELECT id, name, phone, email, subject, message, status,
                   customer_id, order_id, admin_reply, replied_at, created_at
            FROM messages
            WHERE id = ${id}
            LIMIT 1
        `;

        if (!result.length) return bad(res, "Message not found.", 404);

        res.setHeader("Cache-Control", "no-store");
        return res.json({ success: true, message: result[0] });
    } catch (error) {
        console.error("Load message details error:", error);
        return bad(res, "Could not load message details.", 500);
    }
});

app.patch("/api/admin/messages/:id/status", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid message ID.");

        const cleanStatus = str(req.body?.status).toLowerCase();
        if (!["read", "unread"].includes(cleanStatus)) return bad(res, "Status must be read or unread.");

        const result = await sql`
            UPDATE messages SET status = ${cleanStatus}
            WHERE id = ${id}
            RETURNING id, name, phone, email, subject, message, status, created_at
        `;

        if (!result.length) return bad(res, "Message not found.", 404);

        return res.json({ success: true, message: `Message marked as ${cleanStatus}.`, data: result[0] });
    } catch (error) {
        console.error("Update message status error:", error);
        return bad(res, "Could not update message status.", 500);
    }
});

// Reply to a customer (the customer sees it in My Account > Support)
app.put("/api/admin/messages/:id/reply", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid message ID.");

        const reply = str((req.body || {}).reply);
        if (!reply || reply.length > 5000) return bad(res, "Please write a reply (maximum 5000 characters).");

        const result = await sql`
            UPDATE messages
            SET admin_reply = ${reply}, replied_at = NOW(), status = 'read'
            WHERE id = ${id}
            RETURNING id, subject, status, admin_reply, replied_at, customer_id
        `;

        if (!result.length) return bad(res, "Message not found.", 404);

        return res.json({ success: true, message: "Reply saved.", data: result[0] });
    } catch (error) {
        console.error("Reply message error:", error);
        return bad(res, "Could not save reply.", 500);
    }
});

app.delete("/api/admin/messages/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid message ID.");

        const result = await sql`DELETE FROM messages WHERE id = ${id} RETURNING id`;
        if (!result.length) return bad(res, "Message not found.", 404);

        return res.json({ success: true, message: "Message deleted successfully." });
    } catch (error) {
        console.error("Delete message error:", error);
        return bad(res, "Could not delete message.", 500);
    }
});

// =====================================
// ADMIN <-> SUPPLIER MESSAGES
// =====================================

app.get("/api/admin/supplier-messages", requireAdmin, async (req, res) => {
    try {
        const supplierId = req.query.supplier_id;
        if (supplierId !== undefined && !isValidId(String(supplierId))) return bad(res, "Invalid supplier ID.");

        const messages = supplierId
            ? await sql`
                SELECT m.id, m.supplier_id, s.supplier_name, m.sender, m.subject, m.message, m.is_read, m.created_at
                FROM supplier_messages m
                LEFT JOIN suppliers s ON s.id = m.supplier_id
                WHERE m.supplier_id = ${String(supplierId)}
                ORDER BY m.id DESC LIMIT 300`
            : await sql`
                SELECT m.id, m.supplier_id, s.supplier_name, m.sender, m.subject, m.message, m.is_read, m.created_at
                FROM supplier_messages m
                LEFT JOIN suppliers s ON s.id = m.supplier_id
                ORDER BY m.id DESC LIMIT 300`;

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, messages });
    } catch (error) {
        console.error("Load supplier messages error:", error);
        bad(res, "Could not load supplier messages.", 500);
    }
});

app.post("/api/admin/supplier-messages", requireAdmin, async (req, res) => {
    try {
        const { supplier_id, subject, message } = req.body || {};
        const cleanSubject = str(subject);
        const cleanMessage = str(message);

        if (!isValidId(String(supplier_id))) return bad(res, "Invalid supplier.");
        if (!cleanSubject || cleanSubject.length > 255) return bad(res, "Please enter a subject.");
        if (!cleanMessage || cleanMessage.length > 5000) return bad(res, "Please enter a message.");

        const supplier = await sql`SELECT id FROM suppliers WHERE id = ${String(supplier_id)} LIMIT 1`;
        if (!supplier.length) return bad(res, "Supplier not found.", 404);

        const result = await sql`
            INSERT INTO supplier_messages (supplier_id, sender, subject, message)
            VALUES (${String(supplier_id)}, 'admin', ${cleanSubject}, ${cleanMessage})
            RETURNING id, supplier_id, sender, subject, created_at
        `;

        res.status(201).json({ success: true, message: "Message sent to supplier.", data: result[0] });
    } catch (error) {
        console.error("Send supplier message error:", error);
        bad(res, "Could not send message.", 500);
    }
});

app.patch("/api/admin/supplier-messages/:id/read", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid message ID.");

        const result = await sql`
            UPDATE supplier_messages SET is_read = TRUE WHERE id = ${id} RETURNING id
        `;

        if (!result.length) return bad(res, "Message not found.", 404);
        res.json({ success: true, message: "Marked as read." });
    } catch (error) {
        console.error("Mark supplier message read error:", error);
        bad(res, "Could not update message.", 500);
    }
});

// =====================================
// SUPPLIER: ORDERS AND MESSAGES
// A supplier sees only orders that contain THEIR products, and only their own items.
// (Uses supplierAuth.requireSupplier from ./supplier-auth)
// =====================================

function getSupplierId(req) {
    const s = req.supplier || req.user || {};
    const id = s.id ?? s.supplier_id ?? s.sub;
    return id !== undefined && id !== null && /^\d+$/.test(String(id)) ? String(id) : null;
}

function requireSupplierId(req, res, next) {
    const id = getSupplierId(req);
    if (!id) return bad(res, "Supplier session is invalid.", 401);
    req.supplierId = id;
    next();
}

app.get("/api/supplier/orders", supplierAuth.requireSupplier, requireSupplierId, async (req, res) => {
    try {
        const orders = await sql`
            SELECT o.id, o.order_number, o.status, o.delivery_status, o.tracking_info,
                   o.payment_method, o.payment_status, o.delivery_address,
                   COALESCE(o.delivery_name, c.name) AS customer_name,
                   COALESCE(o.delivery_phone, c.phone) AS customer_phone,
                   o.created_at
            FROM orders o
            LEFT JOIN customers c ON c.id = o.customer_id
            WHERE o.is_archived = FALSE
              AND EXISTS (
                  SELECT 1 FROM order_items oi
                  JOIN supplier_products sp ON sp.product_id = oi.product_id
                  WHERE oi.order_id = o.id AND sp.supplier_id = ${req.supplierId}
              )
            ORDER BY o.id DESC
            LIMIT 200
        `;

        let items = [];

        if (orders.length) {
            const ids = JSON.stringify(orders.map(o => Number(o.id)));
            items = await sql`
                SELECT oi.order_id, oi.product_id, oi.product_name, oi.unit_price, oi.quantity, oi.subtotal
                FROM order_items oi
                WHERE oi.order_id IN (SELECT value::bigint FROM jsonb_array_elements_text(${ids}::jsonb))
                  AND EXISTS (
                      SELECT 1 FROM supplier_products sp
                      WHERE sp.product_id = oi.product_id AND sp.supplier_id = ${req.supplierId}
                  )
                ORDER BY oi.id ASC
            `;
        }

        const grouped = new Map();
        for (const item of items) {
            const key = String(item.order_id);
            if (!grouped.has(key)) grouped.set(key, []);
            grouped.get(key).push(item);
        }

        res.setHeader("Cache-Control", "no-store");
        res.json({
            success: true,
            orders: orders.map(o => ({ ...o, items: grouped.get(String(o.id)) || [] }))
        });
    } catch (error) {
        console.error("Supplier orders error:", error);
        bad(res, "Could not load orders.", 500);
    }
});

app.put("/api/supplier/orders/:id/delivery", supplierAuth.requireSupplier, requireSupplierId, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidId(id)) return bad(res, "Invalid order ID.");

        const deliveryStatus = str((req.body || {}).delivery_status).toLowerCase();
        const tracking = (req.body || {}).tracking_info;

        if (deliveryStatus && !SUPPLIER_DELIVERY_ALLOWED.includes(deliveryStatus)) {
            return bad(res, "You are not allowed to set this delivery status.", 403);
        }
        if (!deliveryStatus && (tracking === undefined || tracking === null)) {
            return bad(res, "Provide a delivery status or tracking information.");
        }

        const related = await sql`
            SELECT o.id, o.status
            FROM orders o
            WHERE o.id = ${id}
              AND EXISTS (
                  SELECT 1 FROM order_items oi
                  JOIN supplier_products sp ON sp.product_id = oi.product_id
                  WHERE oi.order_id = o.id AND sp.supplier_id = ${req.supplierId}
              )
            LIMIT 1
        `;

        if (!related.length) return bad(res, "Order not found.", 404);

        // the admin must confirm the order first
        if (!["confirmed", "processing", "shipped"].includes(related[0].status)) {
            return bad(res, "The admin has not confirmed this order yet.", 409);
        }

        const outcome = await applyOrderUpdate(
            id,
            { delivery_status: deliveryStatus || undefined, tracking_info: tracking },
            `supplier:${req.supplierId}`
        );

        if (outcome.error) return bad(res, outcome.error.message, outcome.error.code);

        res.json({
            success: true,
            message: "Delivery updated.",
            order: {
                id: outcome.order.id,
                status: outcome.order.status,
                delivery_status: outcome.order.delivery_status,
                tracking_info: outcome.order.tracking_info
            }
        });
    } catch (error) {
        console.error("Supplier delivery update error:", error);
        bad(res, "Could not update delivery.", 500);
    }
});

app.get("/api/supplier/messages", supplierAuth.requireSupplier, requireSupplierId, async (req, res) => {
    try {
        const messages = await sql`
            SELECT id, sender, subject, message, is_read, created_at
            FROM supplier_messages
            WHERE supplier_id = ${req.supplierId}
            ORDER BY id DESC
            LIMIT 200
        `;

        await sql`
            UPDATE supplier_messages SET is_read = TRUE
            WHERE supplier_id = ${req.supplierId} AND sender = 'admin' AND is_read = FALSE
        `;

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, messages });
    } catch (error) {
        console.error("Supplier messages error:", error);
        bad(res, "Could not load messages.", 500);
    }
});

app.post("/api/supplier/messages", supplierAuth.requireSupplier, requireSupplierId, contactLimiter, async (req, res) => {
    try {
        const { subject, message } = req.body || {};
        const cleanSubject = str(subject);
        const cleanMessage = str(message);

        if (!cleanSubject || cleanSubject.length > 255) return bad(res, "Please enter a subject.");
        if (!cleanMessage || cleanMessage.length > 5000) return bad(res, "Please enter a message.");

        const result = await sql`
            INSERT INTO supplier_messages (supplier_id, sender, subject, message)
            VALUES (${req.supplierId}, 'supplier', ${cleanSubject}, ${cleanMessage})
            RETURNING id, subject, created_at
        `;

        res.status(201).json({ success: true, message: "Message sent to admin.", data: result[0] });
    } catch (error) {
        console.error("Supplier send message error:", error);
        bad(res, "Could not send message.", 500);
    }
});

// =====================================
// PROTECTED ADMIN PAGES
// (checked on the decoded path, so encoded URLs cannot bypass the login check)
// =====================================

const protectedPages = new Set([
    "dashboard.html",
    "products.html",
    "orders.html",
    "customers.html",
    "services.html",
    "messages.html",
    "suppliers.html",
    "categories.html",
    "settings.html",
    "payments.html",
    "delivery.html",
    "supplier-messages.html"
]);

app.use("/pages", (req, res, next) => {
    let pageName;

    try {
        pageName = decodeURIComponent(req.path).replace(/^\/+/, "").toLowerCase();
    } catch {
        return bad(res, "Invalid URL.");
    }

    if (protectedPages.has(pageName)) {
        res.setHeader("Cache-Control", "no-store");
        return requireAdmin(req, res, next);
    }

    next();
});

app.use("/pages", express.static(path.join(__dirname, "..", "pages")));

// =====================================
// 404 + GLOBAL ERROR HANDLER
// =====================================

app.use((req, res) => {
    bad(res, "The requested resource was not found.", 404);
});

app.use((error, req, res, next) => {
    console.error("Unhandled server error:", error);

    if (res.headersSent) return next(error);

    if (error.type === "entity.too.large") return bad(res, "Request body is too large.", 413);

    if (error instanceof SyntaxError && error.status === 400 && "body" in error) {
        return bad(res, "Invalid JSON request.");
    }

    return bad(res, "An unexpected server error occurred.", 500);
});

// =====================================
// START SERVER (migrations first)
// =====================================

(async () => {
    try {
        await runMigrations();
    } catch (error) {
        console.error("Migration error (server will still start):", error);
    }

    app.listen(PORT, () => {
        console.log(`BAZAR GHOR backend running at http://localhost:${PORT}`);
    });
})();
