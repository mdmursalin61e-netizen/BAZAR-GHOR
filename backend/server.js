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

const app = express();
const PORT = process.env.PORT || 5000;

const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_COOKIE = "elite_admin_token";
const COOKIE_MAX_AGE = 8 * 60 * 60;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error("JWT_SECRET is missing or too short.");
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
    publicDataCache.set(key, {
        data,
        expiresAt: Date.now() + PUBLIC_CACHE_TTL
    });
}

function clearPublicCache(key) {
    publicDataCache.delete(key);
}

function setPublicCacheHeaders(res) {
    res.setHeader(
        "Cache-Control",
        "public, max-age=15, stale-while-revalidate=30"
    );
}

// =====================================
// SECURITY CONFIGURATION
// =====================================

app.disable("x-powered-by");

app.use(helmet({
    contentSecurityPolicy: false
}));

app.use(express.json({
    limit: "100kb"
}));

app.use(express.urlencoded({
    extended: true,
    limit: "100kb",
    parameterLimit: 100
}));

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
    limits: {
        fileSize: 5 * 1024 * 1024,
        files: 1
    },
    fileFilter: (req, file, callback) => {
        if (!Object.keys(allowedImageTypes).includes(file.mimetype)) {
            return callback(
                new Error("Only JPG, PNG, WEBP and GIF images are allowed.")
            );
        }

        callback(null, true);
    }
});

// =====================================
// RATE LIMITERS
// =====================================

const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many login attempts. Please try again after 15 minutes."
    }
});

const registrationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many registration attempts. Please try again later."
    }
});

const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many messages submitted. Please try again later."
    }
});

const orderLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many order attempts. Please try again later."
    }
});

const imageUploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many image uploads. Please try again later."
    }
});

// =====================================
// COOKIE HELPERS
// =====================================

function getAdminToken(req) {
    const cookieHeader = req.headers.cookie || "";
    const cookies = cookieHeader.split(";");

    const adminCookie = cookies.find(cookie =>
        cookie.trim().startsWith(`${TOKEN_COOKIE}=`)
    );

    if (!adminCookie) return null;

    try {
        return decodeURIComponent(
            adminCookie.trim().substring(TOKEN_COOKIE.length + 1)
        );
    } catch {
        return null;
    }
}

function setAdminCookie(res, token) {
    let cookie =
        `${TOKEN_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${COOKIE_MAX_AGE}`;

    if (process.env.NODE_ENV === "production") {
        cookie += "; Secure";
    }

    res.setHeader("Set-Cookie", cookie);
}

function clearAdminCookie(res) {
    let cookie =
        `${TOKEN_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;

    if (process.env.NODE_ENV === "production") {
        cookie += "; Secure";
    }

    res.setHeader("Set-Cookie", cookie);
}

// =====================================
// ADMIN AUTHENTICATION
// =====================================

async function requireAdmin(req, res, next) {
    const token = getAdminToken(req);

    if (!token) {
        return res.status(401).json({
            success: false,
            message: "Please login first."
        });
    }

    let decoded;

    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
        clearAdminCookie(res);

        return res.status(401).json({
            success: false,
            message: "Session expired. Please login again."
        });
    }

    if (!decoded.sub) {
        clearAdminCookie(res);

        return res.status(401).json({
            success: false,
            message: "Invalid session."
        });
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

            return res.status(401).json({
                success: false,
                message: "Admin account is inactive."
            });
        }

        req.admin = admins[0];
        return next();

    } catch (error) {
        console.error("Admin authentication database error:", error);

        return res.status(503).json({
            success: false,
            message: "Authentication service is temporarily unavailable."
        });
    }
}

// =====================================
// STATIC ASSETS AND UPLOADED IMAGES
// =====================================

app.use("/assets", express.static(
    path.join(__dirname, "..", "assets"),
    {
        maxAge: "1d",
        etag: true,
        lastModified: true
    }
));

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
    res.json({
        success: true,
        message: "Backend is running."
    });
});

app.get("/api/health/db", async (req, res) => {
    try {
        const time = await testConnection();

        res.json({
            success: true,
            message: "Database connected.",
            database_time: time
        });

    } catch (error) {
        console.error("DB health check error:", error);

        res.status(503).json({
            success: false,
            message: "Database connection failed."
        });
    }
});

// =====================================
// CUSTOMER REGISTRATION
// =====================================

app.post(
    "/api/customers/register",
    registrationLimiter,
    async (req, res) => {
        try {
            const { name, email, phone } = req.body || {};

            const cleanName =
                typeof name === "string" ? name.trim() : "";

            const cleanEmail =
                typeof email === "string"
                    ? email.trim().toLowerCase()
                    : "";

            const cleanPhone =
                typeof phone === "string" ? phone.trim() : "";

            if (!cleanName || cleanName.length > 150) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid name."
                });
            }

            if (
                !cleanEmail ||
                cleanEmail.length > 255 ||
                !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid email address."
                });
            }

            if (!cleanPhone || cleanPhone.length > 30) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid phone number."
                });
            }

            const existingCustomer = await sql`
                SELECT id
                FROM customers
                WHERE LOWER(email) = ${cleanEmail}
                LIMIT 1
            `;

            if (existingCustomer.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: "This email is already registered."
                });
            }

            const result = await sql`
                INSERT INTO customers (name, email, phone)
                VALUES (${cleanName}, ${cleanEmail}, ${cleanPhone})
                RETURNING id, name, email, phone, created_at
            `;

            return res.status(201).json({
                success: true,
                message: "Registration successful.",
                customer: result[0]
            });

        } catch (error) {
            console.error("Customer registration error:", error);

            return res.status(500).json({
                success: false,
                message: "Registration failed due to a server error."
            });
        }
    }
);

// =====================================
// PUBLIC CONTACT MESSAGE API
// =====================================

app.post(
    "/api/messages",
    contactLimiter,
    async (req, res) => {
        try {
            const {
                name,
                phone,
                email,
                subject,
                message
            } = req.body || {};

            const cleanName =
                typeof name === "string" ? name.trim() : "";

            const cleanPhone =
                typeof phone === "string" ? phone.trim() : "";

            const cleanEmail =
                typeof email === "string"
                    ? email.trim().toLowerCase()
                    : "";

            const cleanSubject =
                typeof subject === "string" ? subject.trim() : "";

            const cleanMessage =
                typeof message === "string" ? message.trim() : "";

            if (!cleanName || cleanName.length > 150) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid name."
                });
            }

            if (!cleanPhone || cleanPhone.length > 30) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid phone number."
                });
            }

            if (
                cleanEmail &&
                (
                    cleanEmail.length > 255 ||
                    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid email address."
                });
            }

            if (!cleanSubject || cleanSubject.length > 255) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a subject."
                });
            }

            if (!cleanMessage || cleanMessage.length > 5000) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a message."
                });
            }

            const result = await sql`
                INSERT INTO messages (
                    name,
                    phone,
                    email,
                    subject,
                    message,
                    status
                )
                VALUES (
                    ${cleanName},
                    ${cleanPhone},
                    ${cleanEmail || null},
                    ${cleanSubject},
                    ${cleanMessage},
                    'unread'
                )
                RETURNING
                    id,
                    name,
                    subject,
                    status,
                    created_at
            `;

            return res.status(201).json({
                success: true,
                message: "Your message has been sent successfully.",
                data: result[0]
            });

        } catch (error) {
            console.error("Contact message submission error:", error);

            return res.status(500).json({
                success: false,
                message: "Could not send your message. Please try again."
            });
        }
    }
);

// =====================================
// ADMIN LOGIN
// =====================================

app.post(
    "/api/admin/login",
    adminLoginLimiter,
    async (req, res) => {
        try {
            const { email, password } = req.body || {};

            if (
                typeof email !== "string" ||
                typeof password !== "string" ||
                !email.trim() ||
                !password ||
                email.length > 255 ||
                password.length > 128
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Email and password are required."
                });
            }

            const normalizedEmail = email.trim().toLowerCase();

            const admins = await sql`
                SELECT id, name, email, password_hash, role, is_active
                FROM admins
                WHERE LOWER(email) = ${normalizedEmail}
                LIMIT 1
            `;

            if (admins.length === 0 || !admins[0].is_active) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid email or password."
                });
            }

            const admin = admins[0];

            const passwordMatches = await bcrypt.compare(
                password,
                admin.password_hash
            );

            if (!passwordMatches) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid email or password."
                });
            }

            const token = jwt.sign(
                { role: admin.role },
                JWT_SECRET,
                {
                    subject: String(admin.id),
                    expiresIn: "8h",
                    algorithm: "HS256"
                }
            );

            setAdminCookie(res, token);
            res.setHeader("Cache-Control", "no-store");

            return res.json({
                success: true,
                message: "Admin login successful.",
                admin: {
                    id: admin.id,
                    name: admin.name,
                    email: admin.email,
                    role: admin.role
                }
            });

        } catch (error) {
            console.error("Admin login error:", error);

            return res.status(500).json({
                success: false,
                message: "Login failed due to a server error."
            });
        }
    }
);

// =====================================
// CHECK ADMIN SESSION
// =====================================

app.get("/api/admin/me", requireAdmin, (req, res) => {
    res.setHeader("Cache-Control", "no-store");

    res.json({
        success: true,
        admin: req.admin
    });
});

// =====================================
// DASHBOARD STATISTICS
// =====================================

app.get("/api/admin/dashboard-stats", requireAdmin, async (req, res) => {
    try {
        const result = await sql`
            SELECT
                (SELECT COUNT(*) FROM products) AS total_products,
                (SELECT COUNT(*) FROM orders WHERE is_archived = FALSE) AS total_orders,
                (SELECT COUNT(*) FROM customers) AS total_customers,
                (SELECT COUNT(*) FROM messages) AS total_messages
        `;

        const stats = result[0];

        res.setHeader("Cache-Control", "no-store");

        res.json({
            success: true,
            statistics: {
                totalProducts: Number(stats.total_products),
                totalOrders: Number(stats.total_orders),
                totalCustomers: Number(stats.total_customers),
                totalMessages: Number(stats.total_messages)
            }
        });

    } catch (error) {
        console.error("Dashboard statistics error:", error);

        res.status(500).json({
            success: false,
            message: "Could not load dashboard statistics."
        });
    }
});

// =====================================
// PUBLIC PRODUCTS
// =====================================

app.get("/api/products", async (req, res) => {
    try {
        let products = getPublicCache("products");

        if (!products) {
            products = await sql`
                SELECT
                    id,
                    name,
                    description,
                    price,
                    stock_quantity,
                    image_url
                FROM products
                WHERE is_active = TRUE
                ORDER BY id DESC
            `;

            setPublicCache("products", products);
        }

        setPublicCacheHeaders(res);

        return res.json({
            success: true,
            products
        });

    } catch (error) {
        console.error("Public products error:", error);

        return res.status(500).json({
            success: false,
            message: "Could not load products."
        });
    }
});

// =====================================
// PUBLIC SERVICES
// =====================================

app.get("/api/services", async (req, res) => {
    try {
        let services = getPublicCache("services");

        if (!services) {
            services = await sql`
                SELECT
                    id,
                    title,
                    slug,
                    description
                FROM services
                WHERE is_active = TRUE
                ORDER BY id DESC
            `;

            setPublicCache("services", services);
        }

        setPublicCacheHeaders(res);

        return res.json({
            success: true,
            services
        });

    } catch (error) {
        console.error("Public services error:", error);

        return res.status(500).json({
            success: false,
            message: "Could not load services."
        });
    }
});

// =====================================
// CUSTOMER ORDER API
// =====================================

app.post(
    "/api/orders",
    orderLimiter,
    async (req, res) => {
        try {
            const {
                name,
                email,
                phone,
                delivery_address,
                payment_method,
                payment_reference,
                items
            } = req.body || {};

            const cleanName =
                typeof name === "string" ? name.trim() : "";

            const cleanEmail =
                typeof email === "string"
                    ? email.trim().toLowerCase()
                    : "";

            const cleanPhone =
                typeof phone === "string" ? phone.trim() : "";

            const cleanAddress =
                typeof delivery_address === "string"
                    ? delivery_address.trim()
                    : "";

            const cleanPaymentMethod =
                typeof payment_method === "string"
                    ? payment_method.trim().toLowerCase()
                    : "";

            const cleanReference =
                typeof payment_reference === "string"
                    ? payment_reference.trim()
                    : "";

            if (!cleanName || cleanName.length > 150) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter your name."
                });
            }

            if (!cleanPhone || cleanPhone.length > 30) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid phone number."
                });
            }

            if (!cleanAddress || cleanAddress.length > 1000) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter your delivery address."
                });
            }

            if (
                cleanEmail &&
                (
                    cleanEmail.length > 255 ||
                    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid email address."
                });
            }

            if (!["nagad", "bkash", "cod"].includes(cleanPaymentMethod)) {
                return res.status(400).json({
                    success: false,
                    message: "Please select a valid payment method."
                });
            }

            if (
                ["nagad", "bkash"].includes(cleanPaymentMethod) &&
                (!cleanReference || cleanReference.length > 100)
            ) {
                return res.status(400).json({
                    success: false,
                    message: `Please enter your ${cleanPaymentMethod === "bkash" ? "bKash" : "Nagad"} Transaction ID.`
                });
            }

            if (
                !Array.isArray(items) ||
                items.length === 0 ||
                items.length > 50
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Your cart is empty or invalid."
                });
            }

            const itemMap = new Map();

            for (const item of items) {
                const productId = Number(item?.id);
                const quantity = Number(item?.quantity);

                if (
                    !Number.isSafeInteger(productId) ||
                    productId <= 0 ||
                    !Number.isSafeInteger(quantity) ||
                    quantity <= 0 ||
                    quantity > 100
                ) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid product or quantity."
                    });
                }

                const newQuantity =
                    (itemMap.get(productId) || 0) + quantity;

                if (newQuantity > 100) {
                    return res.status(400).json({
                        success: false,
                        message: "Maximum quantity per product is 100."
                    });
                }

                itemMap.set(productId, newQuantity);
            }

            const cleanItems = Array.from(itemMap.entries()).map(
                ([id, quantity]) => ({
                    product_id: id,
                    quantity
                })
            );

            const orderNumber =
                "ESG-" +
                Date.now() +
                "-" +
                crypto.randomBytes(3).toString("hex").toUpperCase();

            const result = await sql`
                WITH input_items AS MATERIALIZED (
                    SELECT
                        product_id,
                        SUM(quantity)::INTEGER AS quantity
                    FROM jsonb_to_recordset(
                        ${JSON.stringify(cleanItems)}::jsonb
                    ) AS item(product_id BIGINT, quantity INTEGER)
                    GROUP BY product_id
                ),

                checked_items AS MATERIALIZED (
                    SELECT
                        p.id,
                        p.name,
                        p.price,
                        i.quantity,
                        (p.price * i.quantity)::NUMERIC(12, 2) AS subtotal
                    FROM input_items i
                    INNER JOIN products p
                        ON p.id = i.product_id
                    WHERE p.is_active = TRUE
                ),

                validation AS MATERIALIZED (
                    SELECT
                        COUNT(*)::INTEGER AS item_count,
                        (SELECT COUNT(*) FROM input_items)::INTEGER AS requested_count,
                        COALESCE(
                            BOOL_AND(p.stock_quantity >= ci.quantity),
                            FALSE
                        ) AS enough_stock
                    FROM checked_items ci
                    INNER JOIN products p
                        ON p.id = ci.id
                ),

                updated_stock AS (
                    UPDATE products p
                    SET
                        stock_quantity = p.stock_quantity - ci.quantity,
                        updated_at = NOW()
                    FROM checked_items ci, validation v
                    WHERE
                        p.id = ci.id
                        AND v.item_count > 0
                        AND v.item_count = v.requested_count
                        AND v.enough_stock = TRUE
                        AND p.stock_quantity >= ci.quantity
                    RETURNING p.id
                ),

                new_customer AS (
                    INSERT INTO customers (name, email, phone)
                    SELECT
                        ${cleanName},
                        ${cleanEmail || null},
                        ${cleanPhone}
                    FROM validation v
                    WHERE
                        v.item_count > 0
                        AND v.item_count = v.requested_count
                        AND v.enough_stock = TRUE
                        AND (SELECT COUNT(*) FROM updated_stock) = v.item_count
                    RETURNING id
                ),

                new_order AS (
                    INSERT INTO orders (
                        customer_id,
                        order_number,
                        total_amount,
                        status,
                        payment_status,
                        payment_method,
                        payment_reference,
                        delivery_address
                    )
                    SELECT
                        c.id,
                        ${orderNumber},
                        (SELECT SUM(subtotal) FROM checked_items),
                        'pending',
                        'unpaid',
                        ${cleanPaymentMethod},
                        ${["nagad", "bkash"].includes(cleanPaymentMethod) ? cleanReference : null},
                        ${cleanAddress}
                    FROM new_customer c
                    RETURNING
                        id,
                        order_number,
                        total_amount,
                        status,
                        payment_status,
                        payment_method,
                        created_at
                ),

                new_order_items AS (
                    INSERT INTO order_items (
                        order_id,
                        product_id,
                        product_name,
                        unit_price,
                        quantity,
                        subtotal
                    )
                    SELECT
                        o.id,
                        ci.id,
                        ci.name,
                        ci.price,
                        ci.quantity,
                        ci.subtotal
                    FROM new_order o
                    CROSS JOIN checked_items ci
                    RETURNING id
                )

                SELECT
                    o.*,
                    (SELECT COUNT(*) FROM new_order_items) AS saved_items
                FROM new_order o
            `;

            if (result.length === 0) {
                return res.status(409).json({
                    success: false,
                    message:
                        "Some products are unavailable or out of stock. Please refresh your cart."
                });
            }

            clearPublicCache("products");

            console.log(
                "Order created successfully:",
                result[0].order_number
            );

            return res.status(201).json({
                success: true,
                message: "Your order has been placed successfully. Payment will be manually verified by the admin.",
                order: result[0]
            });

        } catch (error) {
            console.error("================================");
            console.error("CREATE ORDER ERROR");
            console.error(error);
            console.error("================================");

            return res.status(500).json({
                success: false,
                message: "Could not place your order. Please try again."
            });
        }
    }
);

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
                const message =
                    error.code === "LIMIT_FILE_SIZE"
                        ? "Image must be 5MB or smaller."
                        : error.message || "Image upload failed.";

                return res.status(400).json({
                    success: false,
                    message
                });
            }

            next();
        });
    },
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({
                    success: false,
                    message: "Please select an image."
                });
            }

            const { fileTypeFromBuffer } = await import("file-type");

            const detected = await fileTypeFromBuffer(req.file.buffer);

            if (!detected || !allowedImageTypes[detected.mime]) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid image file. Please select a real JPG, PNG, WEBP or GIF image."
                });
            }

            const extension = allowedImageTypes[detected.mime];

            const filename =
                crypto.randomBytes(20).toString("hex") +
                "." +
                extension;

            const filePath = path.join(uploadDirectory, filename);

            await fs.promises.writeFile(filePath, req.file.buffer, {
                flag: "wx"
            });

            return res.status(201).json({
                success: true,
                message: "Image uploaded successfully.",
                image_url: `/uploads/${filename}`
            });

        } catch (error) {
            console.error("Product image upload error:", error);

            return res.status(500).json({
                success: false,
                message: "Could not upload image."
            });
        }
    }
);

// =====================================
// ADMIN PRODUCTS
// =====================================

app.get("/api/admin/products", requireAdmin, async (req, res) => {
    try {
        const products = await sql`
            SELECT
                id, name, description, price, stock_quantity,
                image_url, is_active, created_at, updated_at
            FROM products
            ORDER BY id DESC
        `;

        res.setHeader("Cache-Control", "no-store");

        res.json({ success: true, products });

    } catch (error) {
        console.error("Load products error:", error);

        res.status(500).json({
            success: false,
            message: "Could not load products."
        });
    }
});

app.post("/api/admin/products", requireAdmin, async (req, res) => {
    try {
        const {
            name,
            description,
            price,
            stock_quantity,
            image_url
        } = req.body || {};

        const cleanName =
            typeof name === "string" ? name.trim() : "";

        const cleanDescription =
            typeof description === "string"
                ? description.trim()
                : "";

        const cleanImage =
            typeof image_url === "string"
                ? image_url.trim()
                : "";

        const numericPrice = Number(price);
        const numericStock = Number(stock_quantity ?? 0);

        if (!cleanName || cleanName.length > 200) {
            return res.status(400).json({
                success: false,
                message: "Product name is required."
            });
        }

        if (
            price === undefined ||
            price === null ||
            price === "" ||
            !Number.isFinite(numericPrice) ||
            numericPrice < 0
        ) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid product price."
            });
        }

        if (
            !Number.isSafeInteger(numericStock) ||
            numericStock < 0
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid stock quantity."
            });
        }

        const validImage =
            !cleanImage ||
            /^https?:\/\//i.test(cleanImage) ||
            /^\/uploads\/[a-f0-9]{40}\.(jpg|png|webp|gif)$/i.test(cleanImage);

        if (!validImage) {
            return res.status(400).json({
                success: false,
                message: "Invalid image URL."
            });
        }

        const result = await sql`
            INSERT INTO products (
                name, description, price,
                stock_quantity, image_url, is_active
            )
            VALUES (
                ${cleanName},
                ${cleanDescription},
                ${numericPrice},
                ${numericStock},
                ${cleanImage || null},
                TRUE
            )
            RETURNING *
        `;

        clearPublicCache("products");

        res.status(201).json({
            success: true,
            message: "Product added successfully.",
            product: result[0]
        });

    } catch (error) {
        console.error("Add product error:", error);

        res.status(500).json({
            success: false,
            message: "Could not add product."
        });
    }
});

app.put("/api/admin/products/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid product ID."
            });
        }

        const {
            name,
            description,
            price,
            stock_quantity,
            image_url
        } = req.body || {};

        const cleanName =
            typeof name === "string" ? name.trim() : "";

        const cleanDescription =
            typeof description === "string"
                ? description.trim()
                : "";

        const cleanImage =
            typeof image_url === "string"
                ? image_url.trim()
                : "";

        const numericPrice = Number(price);
        const numericStock = Number(stock_quantity ?? 0);

        if (!cleanName || cleanName.length > 200) {
            return res.status(400).json({
                success: false,
                message: "Product name is required."
            });
        }

        if (
            price === undefined ||
            price === null ||
            price === "" ||
            !Number.isFinite(numericPrice) ||
            numericPrice < 0
        ) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid product price."
            });
        }

        if (
            !Number.isSafeInteger(numericStock) ||
            numericStock < 0
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid stock quantity."
            });
        }

        const validImage =
            !cleanImage ||
            /^https?:\/\//i.test(cleanImage) ||
            /^\/uploads\/[a-f0-9]{40}\.(jpg|png|webp|gif)$/i.test(cleanImage);

        if (!validImage) {
            return res.status(400).json({
                success: false,
                message: "Invalid image URL."
            });
        }

        const result = await sql`
            UPDATE products
            SET
                name = ${cleanName},
                description = ${cleanDescription},
                price = ${numericPrice},
                stock_quantity = ${numericStock},
                image_url = ${cleanImage || null},
                updated_at = NOW()
            WHERE id = ${id}
            RETURNING *
        `;

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Product not found."
            });
        }

        clearPublicCache("products");

        res.json({
            success: true,
            message: "Product updated successfully.",
            product: result[0]
        });

    } catch (error) {
        console.error("Update product error:", error);

        res.status(500).json({
            success: false,
            message: "Could not update product."
        });
    }
});

app.delete("/api/admin/products/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid product ID."
            });
        }

        const result = await sql`
            DELETE FROM products
            WHERE id = ${id}
            RETURNING id
        `;

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Product not found."
            });
        }

        clearPublicCache("products");

        res.json({
            success: true,
            message: "Product deleted successfully."
        });

    } catch (error) {
        console.error("Delete product error:", error);

        res.status(500).json({
            success: false,
            message: "Could not delete products. This product may be linked to an order."
        });
    }
});

// =====================================
// ADMIN SERVICES MANAGEMENT
// =====================================

app.get("/api/admin/services", requireAdmin, async (req, res) => {
    try {
        const services = await sql`
            SELECT
                id,
                title,
                slug,
                description,
                is_active,
                created_at
            FROM services
            ORDER BY id DESC
        `;

        res.setHeader("Cache-Control", "no-store");

        res.json({
            success: true,
            services
        });

    } catch (error) {
        console.error("Load services error:", error);

        res.status(500).json({
            success: false,
            message: "Could not load services."
        });
    }
});

app.post("/api/admin/services", requireAdmin, async (req, res) => {
    try {
        const { title, slug, description, is_active } = req.body || {};

        const cleanTitle =
            typeof title === "string" ? title.trim() : "";

        const cleanSlug =
            typeof slug === "string"
                ? slug.trim().toLowerCase()
                : "";

        const cleanDescription =
            typeof description === "string"
                ? description.trim()
                : "";

        if (!cleanTitle || cleanTitle.length > 200) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid service title."
            });
        }

        if (
            !cleanSlug ||
            cleanSlug.length > 200 ||
            !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(cleanSlug)
        ) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid slug using lowercase letters, numbers and hyphens."
            });
        }

        const result = await sql`
            INSERT INTO services (
                title,
                slug,
                description,
                is_active
            )
            VALUES (
                ${cleanTitle},
                ${cleanSlug},
                ${cleanDescription},
                ${is_active !== false}
            )
            RETURNING *
        `;

        clearPublicCache("services");

        res.status(201).json({
            success: true,
            message: "Service added successfully.",
            service: result[0]
        });

    } catch (error) {
        console.error("Add service error:", error);

        res.status(500).json({
            success: false,
            message: "Could not add service. Check whether the slug already exists."
        });
    }
});

app.put("/api/admin/services/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid service ID."
            });
        }

        const { title, slug, description, is_active } = req.body || {};

        const cleanTitle =
            typeof title === "string" ? title.trim() : "";

        const cleanSlug =
            typeof slug === "string"
                ? slug.trim().toLowerCase()
                : "";

        const cleanDescription =
            typeof description === "string"
                ? description.trim()
                : "";

        if (!cleanTitle || cleanTitle.length > 200) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid service title."
            });
        }

        if (
            !cleanSlug ||
            cleanSlug.length > 200 ||
            !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(cleanSlug)
        ) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid slug."
            });
        }

        if (typeof is_active !== "boolean") {
            return res.status(400).json({
                success: false,
                message: "Invalid service status."
            });
        }

        const result = await sql`
            UPDATE services
            SET
                title = ${cleanTitle},
                slug = ${cleanSlug},
                description = ${cleanDescription},
                is_active = ${is_active}
            WHERE id = ${id}
            RETURNING *
        `;

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Service not found."
            });
        }

        clearPublicCache("services");

        res.json({
            success: true,
            message: "Service updated successfully.",
            service: result[0]
        });

    } catch (error) {
        console.error("Update service error:", error);

        res.status(500).json({
            success: false,
            message: "Could not update service. Check whether the slug already exists."
        });
    }
});

app.delete("/api/admin/services/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid service ID."
            });
        }

        const result = await sql`
            DELETE FROM services
            WHERE id = ${id}
            RETURNING id
        `;

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Service not found."
            });
        }

        clearPublicCache("services");

        res.json({
            success: true,
            message: "Service deleted successfully."
        });

    } catch (error) {
        console.error("Delete service error:", error);

        res.status(500).json({
            success: false,
            message: "Could not delete service."
        });
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
                o.id,
                o.customer_id,
                o.order_number,
                o.total_amount,
                o.status,
                o.payment_status,
                o.payment_method,
                o.payment_reference,
                o.delivery_address,
                o.created_at,
                o.is_archived,
                c.name AS customer_name,
                c.phone AS customer_phone,
                c.email AS customer_email
            FROM orders o
            LEFT JOIN customers c
                ON c.id = o.customer_id
            WHERE o.is_archived = ${showArchived}
            ORDER BY o.id DESC
        `;

        res.setHeader("Cache-Control", "no-store");

        res.json({
            success: true,
            orders
        });

    } catch (error) {
        console.error("Load orders error:", error);

        res.status(500).json({
            success: false,
            message: "Could not load orders."
        });
    }
});

// =====================================
// GET ORDER ITEMS
// =====================================

app.get("/api/admin/orders/:id/items", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid order ID."
            });
        }

        const items = await sql`
            SELECT
                id,
                product_id,
                product_name,
                unit_price,
                quantity,
                subtotal
            FROM order_items
            WHERE order_id = ${id}
            ORDER BY id ASC
        `;

        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            items
        });

    } catch (error) {
        console.error("Load order items error:", error);

        return res.status(500).json({
            success: false,
            message: "Could not load order items."
        });
    }
});

// =====================================
// UPDATE ORDER STATUS AND PAYMENT STATUS
// =====================================

app.put("/api/admin/orders/:id/status", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid order ID."
            });
        }

        const { status, payment_status } = req.body || {};

        const cleanStatus =
            typeof status === "string"
                ? status.trim().toLowerCase()
                : null;

        const cleanPaymentStatus =
            typeof payment_status === "string"
                ? payment_status.trim().toLowerCase()
                : null;

        const allowedStatuses = [
            "pending",
            "confirmed",
            "processing",
            "shipped",
            "delivered",
            "cancelled"
        ];

        const allowedPaymentStatuses = [
            "unpaid",
            "pending",
            "paid",
            "failed",
            "refunded"
        ];

        if (!cleanStatus && !cleanPaymentStatus) {
            return res.status(400).json({
                success: false,
                message: "Provide an order or payment status."
            });
        }

        if (
            cleanStatus &&
            !allowedStatuses.includes(cleanStatus)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid order status."
            });
        }

        if (
            cleanPaymentStatus &&
            !allowedPaymentStatuses.includes(cleanPaymentStatus)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid payment status."
            });
        }

        const result = await sql`
            UPDATE orders
            SET
                status = COALESCE(${cleanStatus}, status),
                payment_status = COALESCE(
                    ${cleanPaymentStatus},
                    payment_status
                )
            WHERE id = ${id}
            RETURNING *
        `;

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Order not found."
            });
        }

        res.json({
            success: true,
            message: "Order status updated successfully.",
            order: result[0]
        });

    } catch (error) {
        console.error("Update order status error:", error);

        res.status(500).json({
            success: false,
            message: "Could not update order status."
        });
    }
});

// =====================================
// ARCHIVE ORDER
// =====================================

app.patch("/api/admin/orders/:id/archive", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid order ID."
            });
        }

        const result = await sql`
            UPDATE orders
            SET is_archived = TRUE
            WHERE id = ${id}
              AND is_archived = FALSE
            RETURNING id
        `;

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Active order not found."
            });
        }

        res.json({
            success: true,
            message: "Order archived successfully."
        });

    } catch (error) {
        console.error("Archive order error:", error);

        res.status(500).json({
            success: false,
            message: "Could not archive order."
        });
    }
});

// =====================================
// RESTORE ARCHIVED ORDER
// =====================================

app.patch("/api/admin/orders/:id/restore", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid order ID."
            });
        }

        const result = await sql`
            UPDATE orders
            SET is_archived = FALSE
            WHERE id = ${id}
              AND is_archived = TRUE
            RETURNING id
        `;

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Archived order not found."
            });
        }

        res.json({
            success: true,
            message: "Order restored successfully."
        });

    } catch (error) {
        console.error("Restore order error:", error);

        res.status(500).json({
            success: false,
            message: "Could not restore order."
        });
    }
});

// =====================================
// PERMANENTLY DELETE ORDER
// =====================================

app.delete("/api/admin/orders/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid order ID."
            });
        }

        const existing = await sql`
            SELECT id
            FROM orders
            WHERE id = ${id}
              AND is_archived = TRUE
            LIMIT 1
        `;

        if (existing.length === 0) {
            return res.status(400).json({
                success: false,
                message: "Only archived orders can be permanently deleted."
            });
        }

        await sql`
            DELETE FROM order_items
            WHERE order_id = ${id}
        `;

        const deletedOrder = await sql`
            DELETE FROM orders
            WHERE id = ${id}
              AND is_archived = TRUE
            RETURNING id
        `;

        if (deletedOrder.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Order not found."
            });
        }

        res.json({
            success: true,
            message: "Order permanently deleted."
        });

    } catch (error) {
        console.error("Permanent delete order error:", error);

        res.status(500).json({
            success: false,
            message: "Could not permanently delete order."
        });
    }
});

// =====================================
// ADMIN CUSTOMERS
// =====================================

// =====================================
// ADMIN CUSTOMERS
// =====================================

// GET ACTIVE / ARCHIVED CUSTOMERS
app.get("/api/admin/customers", requireAdmin, async (req, res) => {
    try {
        const showArchived = req.query.archived === "true";

        const customers = await sql`
            SELECT id, name, email, phone, created_at, is_archived
            FROM customers
            WHERE is_archived = ${showArchived}
            ORDER BY id DESC
        `;

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, customers });

    } catch (error) {
        console.error("Load customers error:", error);
        res.status(500).json({
            success: false,
            message: "Could not load customers."
        });
    }
});

// EXPORT CUSTOMERS CSV
app.get("/api/admin/customers/export.csv", requireAdmin, async (req, res) => {
    try {
        const showArchived = req.query.archived === "true";

        const customers = await sql`
            SELECT id, name, email, phone, created_at, is_archived
            FROM customers
            WHERE is_archived = ${showArchived}
            ORDER BY id DESC
        `;

        const csvCell = (value) => {
            let text = value == null ? "" : String(value);

            if (/^\s*[=+\-@\t\r]/.test(text)) {
                text = "'" + text;
            }

            return `"${text.replace(/"/g, '""')}"`;
        };

        const rows = [
            ["ID", "Name", "Email", "Phone", "Created At", "Archived"],
            ...customers.map(customer => [
                customer.id,
                customer.name,
                customer.email,
                customer.phone,
                customer.created_at,
                customer.is_archived ? "Yes" : "No"
            ])
        ];

        const csv = "\uFEFF" + rows
            .map(row => row.map(csvCell).join(","))
            .join("\r\n");

        res.setHeader("Cache-Control", "no-store");
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader(
            "Content-Disposition",
            `attachment; filename="customers-${showArchived ? "archived" : "active"}.csv"`
        );

        res.send(csv);

    } catch (error) {
        console.error("Export customers error:", error);
        res.status(500).json({
            success: false,
            message: "Could not export customers."
        });
    }
});

// GET CUSTOMER DETAILS
app.get("/api/admin/customers/:id", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid customer ID."
            });
        }

        const result = await sql`
            SELECT id, name, email, phone, created_at, is_archived
            FROM customers
            WHERE id = ${id}
            LIMIT 1
        `;

        if (!result.length) {
            return res.status(404).json({
                success: false,
                message: "Customer not found."
            });
        }

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, customer: result[0] });

    } catch (error) {
        console.error("Customer details error:", error);
        res.status(500).json({
            success: false,
            message: "Could not load customer details."
        });
    }
});

// UPDATE CUSTOMER
app.put("/api/admin/customers/:id", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid customer ID."
            });
        }

        const name = typeof req.body.name === "string"
            ? req.body.name.trim()
            : "";

        const emailInput = typeof req.body.email === "string"
            ? req.body.email.trim()
            : "";

        const phoneInput = typeof req.body.phone === "string"
            ? req.body.phone.trim()
            : "";

        if (!name || name.length > 150) {
            return res.status(400).json({
                success: false,
                message: "Name is required and must be within 150 characters."
            });
        }

        if (emailInput.length > 255 ||
            (emailInput && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput))) {
            return res.status(400).json({
                success: false,
                message: "Please enter a valid email address."
            });
        }

        if (phoneInput.length > 30) {
            return res.status(400).json({
                success: false,
                message: "Phone number is too long."
            });
        }

        const email = emailInput || null;
        const phone = phoneInput || null;

        if (email) {
            const duplicate = await sql`
                SELECT id FROM customers
                WHERE LOWER(email) = LOWER(${email})
                AND id <> ${id}
                LIMIT 1
            `;

            if (duplicate.length) {
                return res.status(409).json({
                    success: false,
                    message: "This email is already used by another customer."
                });
            }
        }

        const updated = await sql`
            UPDATE customers
            SET name = ${name},
                email = ${email},
                phone = ${phone}
            WHERE id = ${id}
            RETURNING id, name, email, phone, created_at, is_archived
        `;

        if (!updated.length) {
            return res.status(404).json({
                success: false,
                message: "Customer not found."
            });
        }

        res.json({
            success: true,
            message: "Customer updated successfully.",
            customer: updated[0]
        });

    } catch (error) {
        console.error("Update customer error:", error);
        res.status(500).json({
            success: false,
            message: "Could not update customer."
        });
    }
});

// CUSTOMER ORDER HISTORY
app.get("/api/admin/customers/:id/orders", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid customer ID."
            });
        }

        const customer = await sql`
            SELECT id FROM customers WHERE id = ${id} LIMIT 1
        `;

        if (!customer.length) {
            return res.status(404).json({
                success: false,
                message: "Customer not found."
            });
        }

        const orders = await sql`
            SELECT
                id, customer_id, order_number, total_amount,
                status, payment_status, payment_method,
                payment_reference, delivery_address,
                created_at, is_archived
            FROM orders
            WHERE customer_id = ${id}
            ORDER BY id DESC
        `;

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true, orders });

    } catch (error) {
        console.error("Customer orders error:", error);
        res.status(500).json({
            success: false,
            message: "Could not load customer orders."
        });
    }
});

// ARCHIVE CUSTOMER
app.patch("/api/admin/customers/:id/archive", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid customer ID."
            });
        }

        const result = await sql`
            UPDATE customers
            SET is_archived = TRUE
            WHERE id = ${id} AND is_archived = FALSE
            RETURNING id
        `;

        if (!result.length) {
            return res.status(404).json({
                success: false,
                message: "Active customer not found."
            });
        }

        res.json({
            success: true,
            message: "Customer archived successfully."
        });

    } catch (error) {
        console.error("Archive customer error:", error);
        res.status(500).json({
            success: false,
            message: "Could not archive customer."
        });
    }
});

// RESTORE CUSTOMER
app.patch("/api/admin/customers/:id/restore", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid customer ID."
            });
        }

        const result = await sql`
            UPDATE customers
            SET is_archived = FALSE
            WHERE id = ${id} AND is_archived = TRUE
            RETURNING id
        `;

        if (!result.length) {
            return res.status(404).json({
                success: false,
                message: "Archived customer not found."
            });
        }

        res.json({
            success: true,
            message: "Customer restored successfully."
        });

    } catch (error) {
        console.error("Restore customer error:", error);
        res.status(500).json({
            success: false,
            message: "Could not restore customer."
        });
    }
});

// PERMANENTLY DELETE CUSTOMER
app.delete("/api/admin/customers/:id", requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid customer ID."
            });
        }

        const customer = await sql`
            SELECT id, is_archived
            FROM customers
            WHERE id = ${id}
            LIMIT 1
        `;

        if (!customer.length) {
            return res.status(404).json({
                success: false,
                message: "Customer not found."
            });
        }

        if (!customer[0].is_archived) {
            return res.status(400).json({
                success: false,
                message: "Archive the customer before permanently deleting."
            });
        }

        const orderCount = await sql`
            SELECT COUNT(*) AS total
            FROM orders
            WHERE customer_id = ${id}
        `;

        if (Number(orderCount[0].total) > 0) {
            return res.status(409).json({
                success: false,
                message: "This customer has orders. Archive the customer instead to preserve order history."
            });
        }

        await sql`
            DELETE FROM customers
            WHERE id = ${id} AND is_archived = TRUE
        `;

        res.json({
            success: true,
            message: "Customer permanently deleted."
        });

    } catch (error) {
        console.error("Delete customer error:", error);
        res.status(409).json({
            success: false,
            message: "Could not delete customer. Related records may exist."
        });
    }
});
// =====================================
// ADMIN MESSAGES MANAGEMENT
// =====================================

app.get("/api/admin/messages", requireAdmin, async (req, res) => {
    try {
        const messages = await sql`
            SELECT
                id,
                name,
                phone,
                email,
                subject,
                message,
                status,
                created_at
            FROM messages
            ORDER BY id DESC
        `;

        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            messages
        });

    } catch (error) {
        console.error("Load messages error:", error);

        return res.status(500).json({
            success: false,
            message: "Could not load messages."
        });
    }
});

// =====================================
// GET SINGLE MESSAGE DETAILS
// =====================================

app.get("/api/admin/messages/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid message ID."
            });
        }

        const result = await sql`
            SELECT
                id,
                name,
                phone,
                email,
                subject,
                message,
                status,
                created_at
            FROM messages
            WHERE id = ${id}
            LIMIT 1
        `;

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Message not found."
            });
        }

        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            message: result[0]
        });

    } catch (error) {
        console.error("Load message details error:", error);

        return res.status(500).json({
            success: false,
            message: "Could not load message details."
        });
    }
});

// =====================================
// UPDATE MESSAGE READ / UNREAD STATUS
// =====================================

app.patch("/api/admin/messages/:id/status", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid message ID."
            });
        }

        const cleanStatus =
            typeof req.body?.status === "string"
                ? req.body.status.trim().toLowerCase()
                : "";

        const allowedStatuses = ["read", "unread"];

        if (!allowedStatuses.includes(cleanStatus)) {
            return res.status(400).json({
                success: false,
                message: "Status must be read or unread."
            });
        }

        const result = await sql`
            UPDATE messages
            SET status = ${cleanStatus}
            WHERE id = ${id}
            RETURNING
                id,
                name,
                phone,
                email,
                subject,
                message,
                status,
                created_at
        `;

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Message not found."
            });
        }

        return res.json({
            success: true,
            message: `Message marked as ${cleanStatus}.`,
            data: result[0]
        });

    } catch (error) {
        console.error("Update message status error:", error);

        return res.status(500).json({
            success: false,
            message: "Could not update message status."
        });
    }
});

// =====================================
// DELETE MESSAGE
// =====================================

app.delete("/api/admin/messages/:id", requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid message ID."
            });
        }

        const result = await sql`
            DELETE FROM messages
            WHERE id = ${id}
            RETURNING id
        `;

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Message not found."
            });
        }

        return res.json({
            success: true,
            message: "Message deleted successfully."
        });

    } catch (error) {
        console.error("Delete message error:", error);

        return res.status(500).json({
            success: false,
            message: "Could not delete message."
        });
    }
});

// =====================================
// ADMIN LOGOUT
// =====================================

app.post("/api/admin/logout", (req, res) => {
    clearAdminCookie(res);

    res.setHeader("Cache-Control", "no-store");

    res.json({
        success: true,
        message: "Logged out successfully."
    });
});

// =====================================
// PROTECTED ADMIN PAGES
// =====================================

app.get("/pages/dashboard.html", requireAdmin, (req, res) => {
    res.setHeader("Cache-Control", "no-store");

    res.sendFile(
        path.join(__dirname, "..", "pages", "dashboard.html")
    );
});

app.get("/pages/products.html", requireAdmin, (req, res) => {
    res.setHeader("Cache-Control", "no-store");

    res.sendFile(
        path.join(__dirname, "..", "pages", "products.html")
    );
});

app.get("/pages/orders.html", requireAdmin, (req, res) => {
    res.setHeader("Cache-Control", "no-store");

    res.sendFile(
        path.join(__dirname, "..", "pages", "orders.html")
    );
});

app.get("/pages/customers.html", requireAdmin, (req, res) => {
    res.setHeader("Cache-Control", "no-store");

    res.sendFile(
        path.join(__dirname, "..", "pages", "customers.html")
    );
});

app.get("/pages/services.html", requireAdmin, (req, res) => {
    res.setHeader("Cache-Control", "no-store");

    res.sendFile(
        path.join(__dirname, "..", "pages", "services.html")
    );
});

app.get("/pages/messages.html", requireAdmin, (req, res) => {
    res.setHeader("Cache-Control", "no-store");

    res.sendFile(
        path.join(__dirname, "..", "pages", "messages.html")
    );
});

// =====================================
// PUBLIC STATIC PAGES
// =====================================

app.use("/pages", express.static(
    path.join(__dirname, "..", "pages")
));

// =====================================
// 404 HANDLER
// =====================================

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "The requested resource was not found."
    });
});

// =====================================
// GLOBAL ERROR HANDLER
// =====================================

app.use((error, req, res, next) => {
    console.error("Unhandled server error:", error);

    if (res.headersSent) {
        return next(error);
    }

    if (error.type === "entity.too.large") {
        return res.status(413).json({
            success: false,
            message: "Request body is too large."
        });
    }

    if (error instanceof SyntaxError && error.status === 400 && "body" in error) {
        return res.status(400).json({
            success: false,
            message: "Invalid JSON request."
        });
    }

    return res.status(500).json({
        success: false,
        message: "An unexpected server error occurred."
    });
});

// =====================================
// START SERVER
// =====================================

app.listen(PORT, () => {
    console.log(
        `BAZAR GHOR backend running at http://localhost:${PORT}`
    );
});