const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

module.exports = function createCustomerAuth({ sql, jwtSecret }) {
    if (!sql) {
        throw new Error("[BAZAR GHOR] createCustomerAuth requires a sql client.");
    }

    if (!jwtSecret || typeof jwtSecret !== "string" || jwtSecret.length < 16) {
        throw new Error("[BAZAR GHOR] createCustomerAuth requires a strong jwtSecret.");
    }

    const router = express.Router();

    const COOKIE_NAME = "bazar_customer_token";
    const COOKIE_MAX_AGE = 8 * 60 * 60;
    const DUMMY_HASH = bcrypt.hashSync("dummy-bazar-ghor-customer-password", 10);
    const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    const authLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: 10,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: {
            success: false,
            message: "Too many attempts. Please try again later."
        }
    });

    function normalizePhone(value) {
        return String(value || "").replace(/[^0-9]/g, "");
    }

    function getToken(req) {
        const cookies = (req.headers.cookie || "").split(";");

        const found = cookies.find(item =>
            item.trim().startsWith(COOKIE_NAME + "=")
        );

        if (!found) return null;

        try {
            return decodeURIComponent(
                found.trim().substring(COOKIE_NAME.length + 1)
            );
        } catch {
            return null;
        }
    }

    function setCookie(res, token) {
        let cookie =
            `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${COOKIE_MAX_AGE}`;

        if (process.env.NODE_ENV === "production") {
            cookie += "; Secure";
        }

        res.append("Set-Cookie", cookie);
    }

    function clearCookie(res) {
        let cookie =
            `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;

        if (process.env.NODE_ENV === "production") {
            cookie += "; Secure";
        }

        res.append("Set-Cookie", cookie);
    }

    function issueToken(customer) {
        return jwt.sign(
            { type: "customer", platform: "bazar-ghor" },
            jwtSecret,
            {
                subject: String(customer.id),
                expiresIn: "8h",
                algorithm: "HS256"
            }
        );
    }

    async function findActiveCustomer(id) {
        const rows = await sql`
            SELECT id, name, email, phone, account_status, is_archived
            FROM customers
            WHERE id = ${id}
              AND password_hash IS NOT NULL
              AND account_status = 'active'
              AND is_archived = FALSE
            LIMIT 1
        `;

        return rows[0] || null;
    }

    async function requireCustomer(req, res, next) {
        const token = getToken(req);

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Please login first."
            });
        }

        try {
            const decoded = jwt.verify(token, jwtSecret, {
                algorithms: ["HS256"]
            });

            if (
                decoded.type !== "customer" ||
                !decoded.sub ||
                !/^\d+$/.test(String(decoded.sub))
            ) {
                clearCookie(res);

                return res.status(401).json({
                    success: false,
                    message: "Invalid customer session."
                });
            }

            const customer = await findActiveCustomer(decoded.sub);

            if (!customer) {
                clearCookie(res);

                return res.status(401).json({
                    success: false,
                    message: "Customer account is unavailable."
                });
            }

            req.customer = customer;
            return next();

        } catch (error) {
            if (
                error.name === "JsonWebTokenError" ||
                error.name === "TokenExpiredError"
            ) {
                clearCookie(res);

                return res.status(401).json({
                    success: false,
                    message: "Session expired. Please login again."
                });
            }

            console.error("[BAZAR GHOR] Customer authentication error:", error);

            return res.status(503).json({
                success: false,
                message: "Authentication service is unavailable."
            });
        }
    }

    async function optionalCustomer(req, res, next) {
        const token = getToken(req);

        if (!token) {
            req.customer = null;
            return next();
        }

        try {
            const decoded = jwt.verify(token, jwtSecret, {
                algorithms: ["HS256"]
            });

            if (
                decoded.type !== "customer" ||
                !decoded.sub ||
                !/^\d+$/.test(String(decoded.sub))
            ) {
                clearCookie(res);
                req.customer = null;
                return next();
            }

            const customer = await findActiveCustomer(decoded.sub);

            if (!customer) {
                clearCookie(res);
                req.customer = null;
                return next();
            }

            req.customer = customer;
            return next();

        } catch (error) {
            if (
                error.name === "JsonWebTokenError" ||
                error.name === "TokenExpiredError"
            ) {
                clearCookie(res);
                req.customer = null;
                return next();
            }

            console.error("[BAZAR GHOR] Optional customer authentication error:", error);
            req.customer = null;
            return next();
        }
    }

    router.post("/register", authLimiter, async (req, res) => {
        try {
            const body = req.body || {};

            const name = typeof body.name === "string"
                ? body.name.trim()
                : "";

            const phone = typeof body.phone === "string"
                ? body.phone.trim()
                : "";

            const email = typeof body.email === "string"
                ? body.email.trim().toLowerCase()
                : "";

            const password = body.password;

            const normalizedPhone = normalizePhone(phone);

            if (!name || name.length > 150) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid name."
                });
            }

            if (normalizedPhone.length < 8 || normalizedPhone.length > 15) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid phone number."
                });
            }

            if (email && (email.length > 255 || !EMAIL_REGEX.test(email))) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid email address."
                });
            }

            if (
                typeof password !== "string" ||
                password.length < 8 ||
                Buffer.byteLength(password, "utf8") > 72
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Password must be at least 8 characters."
                });
            }

            const existingPhone = await sql`
                SELECT id
                FROM customers
                WHERE REGEXP_REPLACE(phone, '[^0-9]', '', 'g')
                    = ${normalizedPhone}
                LIMIT 1
            `;

            if (existingPhone.length) {
                return res.status(409).json({
                    success: false,
                    message: "This phone number is already associated with a BAZAR GHOR customer account."
                });
            }

            if (email) {
                const existingEmail = await sql`
                    SELECT id
                    FROM customers
                    WHERE LOWER(TRIM(email)) = ${email}
                    LIMIT 1
                `;

                if (existingEmail.length) {
                    return res.status(409).json({
                        success: false,
                        message: "This email is already associated with a BAZAR GHOR customer account."
                    });
                }
            }

            const passwordHash = await bcrypt.hash(password, 12);

            const result = await sql`
                INSERT INTO customers (
                    name,
                    email,
                    phone,
                    password_hash,
                    account_status,
                    is_archived,
                    created_at,
                    updated_at
                )
                VALUES (
                    ${name},
                    ${email || null},
                    ${normalizedPhone},
                    ${passwordHash},
                    'active',
                    FALSE,
                    NOW(),
                    NOW()
                )
                RETURNING id, name, email, phone
            `;

            const customer = result[0];
            setCookie(res, issueToken(customer));
            res.setHeader("Cache-Control", "no-store");

            return res.status(201).json({
                success: true,
                message: "Registration successful.",
                customer
            });

        } catch (error) {
            console.error("[BAZAR GHOR] Customer registration error:", error);

            if (error.code === "23505") {
                return res.status(409).json({
                    success: false,
                    message: "This phone number or email is already registered."
                });
            }

            return res.status(500).json({
                success: false,
                message: "Registration failed."
            });
        }
    });

    router.post("/login", authLimiter, async (req, res) => {
        try {
            const phone = typeof req.body?.phone === "string"
                ? req.body.phone.trim()
                : "";

            const password = req.body?.password;

            const normalizedPhone = normalizePhone(phone);

            if (
                normalizedPhone.length < 8 ||
                normalizedPhone.length > 15 ||
                typeof password !== "string" ||
                !password ||
                password.length > 72
            ) {
                await bcrypt.compare("invalid-password", DUMMY_HASH);

                return res.status(400).json({
                    success: false,
                    message: "Enter a valid phone number and password."
                });
            }

            const rows = await sql`
                SELECT
                    id,
                    name,
                    email,
                    phone,
                    password_hash,
                    account_status,
                    is_archived
                FROM customers
                WHERE REGEXP_REPLACE(phone, '[^0-9]', '', 'g')
                    = ${normalizedPhone}
                  AND password_hash IS NOT NULL
                LIMIT 1
            `;

            const customer = rows[0];

            const passwordMatches = await bcrypt.compare(
                password,
                customer?.password_hash || DUMMY_HASH
            );

            if (
                !customer ||
                !passwordMatches ||
                customer.account_status !== "active" ||
                customer.is_archived
            ) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid phone number or password."
                });
            }

            setCookie(res, issueToken(customer));
            res.setHeader("Cache-Control", "no-store");

            return res.json({
                success: true,
                message: "Login successful.",
                customer: {
                    id: customer.id,
                    name: customer.name,
                    email: customer.email,
                    phone: customer.phone
                }
            });

        } catch (error) {
            console.error("[BAZAR GHOR] Customer login error:", error);

            return res.status(500).json({
                success: false,
                message: "Login failed."
            });
        }
    });

    router.post("/logout", (req, res) => {
        clearCookie(res);
        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            message: "Logged out successfully."
        });
    });

    router.get("/me", requireCustomer, (req, res) => {
        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            customer: req.customer
        });
    });

    return {
        router,
        requireCustomer,
        optionalCustomer
    };
};