function createSupplierAuth({ sql, requireAdmin, jwtSecret }) {
    const express = require("express");
    const bcrypt = require("bcryptjs");
    const jwt = require("jsonwebtoken");
    const rateLimit = require("express-rate-limit");

    const router = express.Router();

    const SUPPLIER_COOKIE = "bazar_supplier_token";
    const COOKIE_MAX_AGE = 8 * 60 * 60;
    const BCRYPT_ROUNDS = 12;
    const DUMMY_PASSWORD_HASH = bcrypt.hashSync("supplier-dummy-timing-guard", 10);

    const supplierLoginLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: 5,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        skipSuccessfulRequests: true,
        message: {
            success: false,
            message: "Too many failed login attempts. Please try again later."
        }
    });

    function getSupplierToken(req) {
        const cookieHeader = req.headers.cookie || "";

        const supplierCookie = cookieHeader
            .split(";")
            .find(cookie =>
                cookie.trim().startsWith(`${SUPPLIER_COOKIE}=`)
            );

        if (!supplierCookie) return null;

        try {
            return decodeURIComponent(
                supplierCookie.trim().substring(
                    SUPPLIER_COOKIE.length + 1
                )
            );
        } catch {
            return null;
        }
    }

    function setSupplierCookie(res, token) {
        let cookie =
            `${SUPPLIER_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${COOKIE_MAX_AGE}`;

        if (process.env.NODE_ENV === "production") {
            cookie += "; Secure";
        }

        res.append("Set-Cookie", cookie);
    }

    function clearSupplierCookie(res) {
        let cookie =
            `${SUPPLIER_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;

        if (process.env.NODE_ENV === "production") {
            cookie += "; Secure";
        }

        res.append("Set-Cookie", cookie);
    }

    // =====================================
    // SUPPLIER AUTHENTICATION MIDDLEWARE
    // =====================================

    async function requireSupplier(req, res, next) {
        const token = getSupplierToken(req);

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Please login first."
            });
        }

        let decoded;

        try {
            decoded = jwt.verify(token, jwtSecret, {
                algorithms: ["HS256"]
            });
        } catch {
            clearSupplierCookie(res);

            return res.status(401).json({
                success: false,
                message: "Your session has expired. Please login again."
            });
        }

        if (decoded.role !== "supplier" || !decoded.sub) {
            clearSupplierCookie(res);

            return res.status(401).json({
                success: false,
                message: "Invalid supplier session."
            });
        }

        try {
            const records = await sql`
                SELECT
                    su.id AS user_id,
                    su.username,
                    su.supplier_id,
                    su.is_active AS user_active,
                    s.supplier_name,
                    s.business_name,
                    s.phone,
                    s.whatsapp,
                    s.district,
                    s.address,
                    s.status AS supplier_status
                FROM supplier_users su
                INNER JOIN suppliers s
                    ON s.id = su.supplier_id
                WHERE su.id = ${decoded.sub}
                LIMIT 1
            `;

            if (
                !records.length ||
                !records[0].user_active ||
                records[0].supplier_status !== "active"
            ) {
                clearSupplierCookie(res);

                return res.status(401).json({
                    success: false,
                    message: "Supplier account is inactive."
                });
            }

            const account = records[0];

            req.supplierUser = {
                id: account.user_id,
                username: account.username
            };

            req.supplier = {
                id: account.supplier_id,
                supplier_name: account.supplier_name,
                business_name: account.business_name,
                phone: account.phone,
                whatsapp: account.whatsapp,
                district: account.district,
                address: account.address,
                status: account.supplier_status,
                role: "supplier"
            };

            return next();

        } catch (error) {
            console.error("Supplier authentication error:", error);

            return res.status(503).json({
                success: false,
                message: "Authentication service is temporarily unavailable."
            });
        }
    }

    // =====================================
    // SUPPLIER LOGIN
    // =====================================

    router.post(
        "/supplier/login",
        supplierLoginLimiter,
        async (req, res) => {
            try {
                const { username, password } = req.body || {};

                const cleanUsername =
                    typeof username === "string"
                        ? username.trim().toLowerCase()
                        : "";

                if (
                    !cleanUsername ||
                    typeof password !== "string" ||
                    password.length < 1 ||
                    password.length > 128
                ) {
                    return res.status(400).json({
                        success: false,
                        message: "Username and password are required."
                    });
                }

                const records = await sql`
                    SELECT
                        su.id,
                        su.username,
                        su.password_hash,
                        su.supplier_id,
                        su.is_active,
                        s.supplier_name,
                        s.business_name,
                        s.status AS supplier_status
                    FROM supplier_users su
                    INNER JOIN suppliers s
                        ON s.id = su.supplier_id
                    WHERE LOWER(su.username) = ${cleanUsername}
                    LIMIT 1
                `;

                const candidate = records[0] || null;
                const hashToCheck =
                    candidate && candidate.password_hash
                        ? candidate.password_hash
                        : DUMMY_PASSWORD_HASH;

                const passwordMatches = await bcrypt.compare(
                    password,
                    hashToCheck
                );

                if (
                    !candidate ||
                    !candidate.password_hash ||
                    !candidate.is_active ||
                    candidate.supplier_status !== "active" ||
                    !passwordMatches
                ) {
                    return res.status(401).json({
                        success: false,
                        message: "Invalid username or password."
                    });
                }

                const token = jwt.sign(
                    { role: "supplier" },
                    jwtSecret,
                    {
                        subject: String(candidate.id),
                        expiresIn: "8h",
                        algorithm: "HS256"
                    }
                );

                setSupplierCookie(res, token);
                res.setHeader("Cache-Control", "no-store");

                return res.json({
                    success: true,
                    message: "Supplier login successful.",
                    supplier: {
                        id: candidate.supplier_id,
                        supplier_name: candidate.supplier_name,
                        business_name: candidate.business_name,
                        username: candidate.username
                    }
                });

            } catch (error) {
                console.error("Supplier login error:", error);

                return res.status(500).json({
                    success: false,
                    message: "Login failed due to a server error."
                });
            }
        }
    );

    // =====================================
    // CHECK SUPPLIER SESSION
    // =====================================

    router.get("/supplier/me", requireSupplier, (req, res) => {
        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            supplier: {
                ...req.supplier,
                username: req.supplierUser.username
            }
        });
    });

    // =====================================
    // SUPPLIER LOGOUT
    // =====================================

    router.post("/supplier/logout", (req, res) => {
        clearSupplierCookie(res);
        res.setHeader("Cache-Control", "no-store");

        return res.json({
            success: true,
            message: "Supplier logged out successfully."
        });
    });

    // =====================================
    // ADMIN: CREATE SUPPLIER LOGIN ACCOUNT
    // =====================================

    router.post(
        "/admin/supplier-users",
        requireAdmin,
        async (req, res) => {
            try {
                const supplierId = req.body?.supplier_id;

                const username =
                    typeof req.body?.username === "string"
                        ? req.body.username.trim().toLowerCase()
                        : "";

                const password = req.body?.password;

                if (!/^[1-9]\d*$/.test(String(supplierId || ""))) {
                    return res.status(400).json({
                        success: false,
                        message: "Please select a valid supplier."
                    });
                }

                if (
                    username.length < 4 ||
                    username.length > 100 ||
                    !/^[a-z0-9._-]+$/.test(username)
                ) {
                    return res.status(400).json({
                        success: false,
                        message: "Username must be 4-100 characters and use lowercase letters, numbers, dots, underscores or hyphens."
                    });
                }

                if (
                    typeof password !== "string" ||
                    password.length < 10 ||
                    password.length > 128
                ) {
                    return res.status(400).json({
                        success: false,
                        message: "Password must be at least 10 characters and no more than 128 characters."
                    });
                }

                const suppliers = await sql`
                    SELECT id
                    FROM suppliers
                    WHERE id = ${supplierId}
                      AND status = 'active'
                    LIMIT 1
                `;

                if (!suppliers.length) {
                    return res.status(404).json({
                        success: false,
                        message: "Active supplier not found."
                    });
                }

                const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

                const result = await sql`
                    INSERT INTO supplier_users (
                        supplier_id,
                        username,
                        password_hash,
                        is_active
                    )
                    VALUES (
                        ${supplierId},
                        ${username},
                        ${passwordHash},
                        TRUE
                    )
                    RETURNING id, supplier_id, username, is_active, created_at
                `;

                res.setHeader("Cache-Control", "no-store");

                return res.status(201).json({
                    success: true,
                    message: "Supplier login account created successfully.",
                    account: result[0]
                });

            } catch (error) {
                console.error("Create supplier account error:", error);

                if (error.code === "23505") {
                    return res.status(409).json({
                        success: false,
                        message: "This supplier already has an account or the username is already taken."
                    });
                }

                return res.status(500).json({
                    success: false,
                    message: "Could not create supplier account."
                });
            }
        }
    );

    // =====================================
    // ADMIN: VIEW SUPPLIER LOGIN ACCOUNTS
    // =====================================

    router.get(
        "/admin/supplier-users",
        requireAdmin,
        async (req, res) => {
            try {
                const accounts = await sql`
                    SELECT
                        su.id,
                        su.supplier_id,
                        su.username,
                        su.is_active,
                        su.created_at,
                        su.updated_at,
                        s.supplier_name,
                        s.business_name,
                        s.status AS supplier_status
                    FROM supplier_users su
                    INNER JOIN suppliers s
                        ON s.id = su.supplier_id
                    ORDER BY su.id DESC
                `;

                res.setHeader("Cache-Control", "no-store");

                return res.json({
                    success: true,
                    accounts
                });

            } catch (error) {
                console.error("Load supplier accounts error:", error);

                return res.status(500).json({
                    success: false,
                    message: "Could not load supplier accounts."
                });
            }
        }
    );

    // =====================================
    // ADMIN: RESET SUPPLIER PASSWORD
    // =====================================

    router.patch(
        "/admin/supplier-users/:id/password",
        requireAdmin,
        async (req, res) => {
            try {
                const id = req.params.id;
                const newPassword = req.body?.new_password;

                if (!/^[1-9]\d*$/.test(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid account ID."
                    });
                }

                if (
                    typeof newPassword !== "string" ||
                    newPassword.length < 10 ||
                    newPassword.length > 128
                ) {
                    return res.status(400).json({
                        success: false,
                        message: "New password must be at least 10 characters and no more than 128 characters."
                    });
                }

                const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

                const result = await sql`
                    UPDATE supplier_users
                    SET
                        password_hash = ${passwordHash},
                        updated_at = NOW()
                    WHERE id = ${id}
                    RETURNING id, supplier_id, username, is_active, updated_at
                `;

                if (!result.length) {
                    return res.status(404).json({
                        success: false,
                        message: "Supplier account not found."
                    });
                }

                res.setHeader("Cache-Control", "no-store");

                return res.json({
                    success: true,
                    message: "Supplier password reset successfully.",
                    account: result[0]
                });

            } catch (error) {
                console.error("Reset supplier password error:", error);

                return res.status(500).json({
                    success: false,
                    message: "Could not reset supplier password."
                });
            }
        }
    );

    // =====================================
    // ADMIN: ACTIVATE / DEACTIVATE ACCOUNT
    // =====================================

    router.patch(
        "/admin/supplier-users/:id/status",
        requireAdmin,
        async (req, res) => {
            try {
                const id = req.params.id;
                const isActive = req.body?.is_active;

                if (!/^[1-9]\d*$/.test(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid account ID."
                    });
                }

                if (typeof isActive !== "boolean") {
                    return res.status(400).json({
                        success: false,
                        message: "Please provide a valid account status."
                    });
                }

                const result = await sql`
                    UPDATE supplier_users
                    SET
                        is_active = ${isActive},
                        updated_at = NOW()
                    WHERE id = ${id}
                    RETURNING id, supplier_id, username, is_active
                `;

                if (!result.length) {
                    return res.status(404).json({
                        success: false,
                        message: "Supplier account not found."
                    });
                }

                res.setHeader("Cache-Control", "no-store");

                return res.json({
                    success: true,
                    message: "Supplier account status updated.",
                    account: result[0]
                });

            } catch (error) {
                console.error("Update supplier account error:", error);

                return res.status(500).json({
                    success: false,
                    message: "Could not update supplier account."
                });
            }
        }
    );

    return {
        router,
        requireSupplier
    };
}

module.exports = createSupplierAuth;