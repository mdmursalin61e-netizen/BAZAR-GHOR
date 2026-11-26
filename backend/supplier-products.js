
function createSupplierProductsRouter({
    sql,
    requireAdmin,
    requireSupplier,
    clearPublicCache = () => {}
}) {
    const express = require("express");
    const router = express.Router();

    const DELETED_BY_ADMIN = "Deleted by Admin";
    const DELETED_BY_SUPPLIER = "Deleted by Supplier";
    const LEGACY_DELETED_NOTE = "Deactivated by Admin";

    const DELIVERY_STATUSES = [
        "preparing",
        "ready_for_dispatch",
        "shipped",
        "delivered"
    ];

    function validId(value) {
        return /^\d+$/.test(String(value)) && Number(value) > 0;
    }

    function money(value) {
        if (value === "" || value === null || value === undefined) {
            return null;
        }

        const n = Number(value);

        if (!Number.isFinite(n) || n < 0 || n > 9999999999.99) {
            return null;
        }

        return Math.round(n * 100) / 100;
    }

    function quantity(value) {
        const n = Number(value);

        if (!Number.isSafeInteger(n) || n < 0 || n > 2147483647) {
            return null;
        }

        return n;
    }

    function profitPercentage(value) {
        const n = Number(value);

        if (!Number.isFinite(n) || n < 0 || n > 100) {
            return null;
        }

        return Math.round(n * 100) / 100;
    }

    function validate(body = {}) {
        const supplierId = Number(body.supplier_id);
        const productId = Number(body.product_id);

        const purchasePrice = money(
            body.purchase_price ?? body.supplier_cost
        );

        const sellingPrice = money(body.selling_price);
        const deliveryCost = money(body.delivery_cost ?? 0);
        const otherCost = money(body.other_cost ?? 0);

        const stock = quantity(
            body.supplier_stock_quantity ?? body.stock_available
        );

        if (!validId(body.supplier_id) || !validId(body.product_id)) {
            return { error: "Please select a valid supplier and product." };
        }

        if (
            purchasePrice === null ||
            deliveryCost === null ||
            otherCost === null
        ) {
            return { error: "Please enter valid cost amounts." };
        }

        if (stock === null) {
            return { error: "Please enter a valid supplier stock quantity." };
        }

        return {
            data: {
                supplierId,
                productId,
                purchasePrice,
                sellingPrice,
                deliveryCost,
                otherCost,
                stock,
                sku: String(
                    body.supplier_sku ?? body.sku ?? ""
                ).trim().slice(0, 100)
            }
        };
    }

    function validateSupplierProduct(body = {}) {
        const name = String(body.name || "").trim();
        const description = String(body.description || "").trim();
        const category = String(body.category || "").trim();
        const sku = String(body.supplier_sku || "").trim();
        const notes = String(body.notes || "").trim();

        const proposedPrice = money(body.proposed_selling_price);
        const purchasePrice = money(body.purchase_price);
        const deliveryCost = money(body.delivery_cost ?? 0);
        const otherCost = money(body.other_cost ?? 0);
        const stock = quantity(body.supplier_stock_quantity);

        const imageUrl = String(body.image_url || "").trim();

        if (!name || name.length > 180) {
            return {
                error: "Product name is required (maximum 180 characters)."
            };
        }

        if (description.length > 10000) {
            return { error: "Description is too long." };
        }

        if (!category || category.length > 100) {
            return { error: "Please enter a valid product category." };
        }

        if (proposedPrice === null || proposedPrice <= 0) {
            return { error: "Please enter a valid proposed selling price." };
        }

        if (
            purchasePrice === null ||
            deliveryCost === null ||
            otherCost === null
        ) {
            return { error: "Please enter valid cost amounts." };
        }

        if (stock === null) {
            return { error: "Please enter a valid stock quantity." };
        }

        if (sku.length > 100 || notes.length > 5000) {
            return { error: "SKU or notes are too long." };
        }

        if (imageUrl) {
            try {
                const parsed = new URL(imageUrl);

                if (!["http:", "https:"].includes(parsed.protocol)) {
                    return { error: "Image URL must use HTTP or HTTPS." };
                }
            } catch {
                return { error: "Please enter a valid image URL." };
            }
        }

        return {
            data: {
                name,
                description,
                category,
                sku,
                notes,
                proposedPrice,
                purchasePrice,
                deliveryCost,
                otherCost,
                stock,
                imageUrl: imageUrl || null
            }
        };
    }

    // =========================================================
    // ADMIN: GET ALL NON-DELETED SUPPLIER PRODUCTS
    // =========================================================

    router.get("/supplier-products", requireAdmin, async (req, res) => {
        try {
            const records = await sql`
                SELECT
                    sp.*,
                    s.supplier_name,
                    s.business_name,
                    s.status AS supplier_status,
                    p.name AS product_name,
                    p.price AS public_selling_price,
                    p.image_url AS product_image,
                    sp.supplier_cost AS purchase_price,
                    sp.stock_available AS supplier_stock_quantity,
                    sp.sku AS supplier_sku,
                    NULL::text AS category,
                    TRUE AS is_available,
                    p.is_active AS is_active,
                    NULL::text AS notes
                FROM supplier_products sp
                JOIN suppliers s ON s.id = sp.supplier_id
                JOIN products p ON p.id = sp.product_id
                WHERE COALESCE(sp.admin_approval_note, '') NOT IN (
                    ${DELETED_BY_ADMIN},
                    ${DELETED_BY_SUPPLIER},
                    ${LEGACY_DELETED_NOTE}
                )
                ORDER BY
                    CASE WHEN sp.approval_status = 'pending'
                    THEN 0 ELSE 1 END,
                    sp.id DESC
            `;

            res.setHeader("Cache-Control", "no-store");

            return res.json({
                success: true,
                supplier_products: records
            });
        } catch (error) {
            console.error("Supplier product list error:", error);

            return res.status(500).json({
                success: false,
                message: "Could not load supplier products."
            });
        }
    });

    // =========================================================
    // ADMIN: ADD EXISTING PRODUCT TO SUPPLIER
    // =========================================================

    router.post("/supplier-products", requireAdmin, async (req, res) => {
        try {
            const validation = validate(req.body);

            if (validation.error) {
                return res.status(400).json({
                    success: false,
                    message: validation.error
                });
            }

            const d = validation.data;

            const suppliers = await sql`
                SELECT id FROM suppliers
                WHERE id = ${d.supplierId}
                AND status = 'active'
                LIMIT 1
            `;

            if (!suppliers.length) {
                return res.status(400).json({
                    success: false,
                    message: "Supplier not found or inactive."
                });
            }

            const products = await sql`
                SELECT id, price FROM products
                WHERE id = ${d.productId}
                LIMIT 1
            `;

            if (!products.length) {
                return res.status(404).json({
                    success: false,
                    message: "Product not found."
                });
            }

            const finalPrice =
                d.sellingPrice ?? Number(products[0].price);

            if (!Number.isFinite(finalPrice) || finalPrice <= 0) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid selling price."
                });
            }

            const result = await sql`
                INSERT INTO supplier_products (
                    supplier_id, product_id, supplier_cost,
                    selling_price, delivery_cost, other_cost,
                    stock_available, sku
                )
                VALUES (
                    ${d.supplierId}, ${d.productId},
                    ${d.purchasePrice}, ${finalPrice},
                    ${d.deliveryCost}, ${d.otherCost},
                    ${d.stock}, ${d.sku || null}
                )
                RETURNING id
            `;

            clearPublicCache();

            return res.status(201).json({
                success: true,
                message: "Supplier product added successfully.",
                id: result[0].id
            });
        } catch (error) {
            console.error("Add supplier product error:", error);

            if (error.code === "23505") {
                return res.status(409).json({
                    success: false,
                    message: "This supplier is already linked to this product."
                });
            }

            return res.status(500).json({
                success: false,
                message: "Could not add supplier product."
            });
        }
    });

    // =========================================================
    // ADMIN: UPDATE SUPPLIER PRODUCT
    // =========================================================

    router.put("/supplier-products/:id", requireAdmin, async (req, res) => {
        try {
            if (!validId(req.params.id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid supplier product ID."
                });
            }

            const validation = validate(req.body);

            if (validation.error) {
                return res.status(400).json({
                    success: false,
                    message: validation.error
                });
            }

            const d = validation.data;

            const suppliers = await sql`
                SELECT id FROM suppliers
                WHERE id = ${d.supplierId}
                AND status = 'active'
                LIMIT 1
            `;

            if (!suppliers.length) {
                return res.status(400).json({
                    success: false,
                    message: "Supplier not found or inactive."
                });
            }

            const products = await sql`
                SELECT id, price FROM products
                WHERE id = ${d.productId}
                LIMIT 1
            `;

            if (!products.length) {
                return res.status(404).json({
                    success: false,
                    message: "Product not found."
                });
            }

            const finalPrice =
                d.sellingPrice ?? Number(products[0].price);

            if (!Number.isFinite(finalPrice) || finalPrice <= 0) {
                return res.status(400).json({
                    success: false,
                    message: "Please enter a valid selling price."
                });
            }

            const result = await sql`
                UPDATE supplier_products
                SET
                    supplier_id = ${d.supplierId},
                    product_id = ${d.productId},
                    supplier_cost = ${d.purchasePrice},
                    selling_price = ${finalPrice},
                    delivery_cost = ${d.deliveryCost},
                    other_cost = ${d.otherCost},
                    stock_available = ${d.stock},
                    sku = ${d.sku || null},
                    updated_at = NOW()
                WHERE id = ${req.params.id}
                AND COALESCE(admin_approval_note, '') NOT IN (
                    ${DELETED_BY_ADMIN},
                    ${DELETED_BY_SUPPLIER},
                    ${LEGACY_DELETED_NOTE}
                )
                RETURNING id
            `;

            if (!result.length) {
                return res.status(404).json({
                    success: false,
                    message: "Supplier product not found."
                });
            }

            clearPublicCache();

            return res.json({
                success: true,
                message: "Supplier product updated successfully."
            });
        } catch (error) {
            console.error("Update supplier product error:", error);

            if (error.code === "23505") {
                return res.status(409).json({
                    success: false,
                    message: "This supplier already has this product."
                });
            }

            return res.status(500).json({
                success: false,
                message: "Could not update supplier product."
            });
        }
    });

    // =========================================================
    // ADMIN: APPROVE OR REJECT SUPPLIER PRODUCT
    // =========================================================

    router.patch("/supplier-products/:id/approval", requireAdmin, async (req, res) => {
        try {
            if (!validId(req.params.id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid supplier product ID."
                });
            }

            const status = req.body.approval_status;
            const note = String(
                req.body.admin_approval_note || ""
            ).trim().slice(0, 3000);

            if (!["approved", "rejected"].includes(status)) {
                return res.status(400).json({
                    success: false,
                    message: "Approval status must be approved or rejected."
                });
            }

            let finalPrice = null;
            let profitPercent = null;

            if (status === "approved") {
                finalPrice = money(
                    req.body.final_selling_price ?? req.body.selling_price
                );

                if (finalPrice === null || finalPrice <= 0) {
                    return res.status(400).json({
                        success: false,
                        message: "A valid final selling price is required for approval."
                    });
                }

                const existing = await sql`
                    SELECT bazar_ghor_profit_percentage
                    FROM supplier_products
                    WHERE id = ${req.params.id}
                    AND COALESCE(admin_approval_note, '') NOT IN (
                        ${DELETED_BY_ADMIN},
                        ${DELETED_BY_SUPPLIER},
                        ${LEGACY_DELETED_NOTE}
                    )
                    LIMIT 1
                `;

                if (!existing.length) {
                    return res.status(404).json({
                        success: false,
                        message: "Supplier product not found."
                    });
                }

                profitPercent =
                    req.body.bazar_ghor_profit_percentage !== undefined
                        ? profitPercentage(
                            req.body.bazar_ghor_profit_percentage
                        )
                        : Number(
                            existing[0].bazar_ghor_profit_percentage || 0
                        );

                if (profitPercent === null) {
                    return res.status(400).json({
                        success: false,
                        message: "Profit percentage must be between 0 and 100."
                    });
                }
            }

            const records = await sql`
                WITH updated_link AS (
                    UPDATE supplier_products
                    SET
                        approval_status = ${status},
                        admin_approval_note = ${note || null},
                        selling_price = CASE
                            WHEN ${status} = 'approved'
                            THEN ${finalPrice}
                            ELSE selling_price
                        END,
                        bazar_ghor_profit_percentage = CASE
                            WHEN ${status} = 'approved'
                            THEN ${profitPercent}
                            ELSE bazar_ghor_profit_percentage
                        END,
                        updated_at = NOW()
                    WHERE id = ${req.params.id}
                    AND COALESCE(admin_approval_note, '') NOT IN (
                        ${DELETED_BY_ADMIN},
                        ${DELETED_BY_SUPPLIER},
                        ${LEGACY_DELETED_NOTE}
                    )
                    RETURNING
                        id, product_id, stock_available,
                        selling_price, approval_status
                ),
                updated_product AS (
                    UPDATE products p
                    SET
                        price = CASE
                            WHEN ul.approval_status = 'approved'
                            THEN ul.selling_price
                            ELSE p.price
                        END,
                        stock_quantity = CASE
                            WHEN ul.approval_status = 'approved'
                            THEN ul.stock_available
                            ELSE p.stock_quantity
                        END,
                        is_active = CASE
                            WHEN ul.approval_status = 'approved'
                            THEN TRUE
                            ELSE FALSE
                        END,
                        updated_at = NOW()
                    FROM updated_link ul
                    WHERE p.id = ul.product_id
                    AND (
                        ul.approval_status = 'approved'
                        OR NOT EXISTS (
                            SELECT 1
                            FROM supplier_products other_sp
                            WHERE other_sp.product_id = p.id
                            AND other_sp.id <> ul.id
                            AND other_sp.approval_status = 'approved'
                            AND COALESCE(
                                other_sp.admin_approval_note, ''
                            ) NOT IN (
                                ${DELETED_BY_ADMIN},
                                ${DELETED_BY_SUPPLIER},
                                ${LEGACY_DELETED_NOTE}
                            )
                        )
                    )
                    RETURNING p.id
                )
                SELECT id, product_id, approval_status
                FROM updated_link
            `;

            if (!records.length) {
                return res.status(404).json({
                    success: false,
                    message: "Supplier product not found."
                });
            }

            clearPublicCache();

            return res.json({
                success: true,
                message: status === "approved"
                    ? "Supplier product approved successfully."
                    : "Supplier product rejected.",
                approval_status: status,
                final_selling_price: finalPrice,
                bazar_ghor_profit_percentage: profitPercent
            });
        } catch (error) {
            console.error("Supplier product approval error:", error);

            return res.status(500).json({
                success: false,
                message: "Could not update product approval."
            });
        }
    });

    // =========================================================
    // SHARED SAFE DELETE FUNCTION
    // =========================================================

    async function safelyDeleteSupplierProduct(
        id,
        deletedNote,
        supplierId = null
    ) {
        const result = supplierId === null
            ? await sql`
                UPDATE supplier_products
                SET
                    approval_status = 'rejected',
                    admin_approval_note = ${deletedNote},
                    updated_at = NOW()
                WHERE id = ${id}
                AND COALESCE(admin_approval_note, '') NOT IN (
                    ${DELETED_BY_ADMIN},
                    ${DELETED_BY_SUPPLIER},
                    ${LEGACY_DELETED_NOTE}
                )
                RETURNING id, product_id
            `
            : await sql`
                UPDATE supplier_products
                SET
                    approval_status = 'rejected',
                    admin_approval_note = ${deletedNote},
                    updated_at = NOW()
                WHERE id = ${id}
                AND supplier_id = ${supplierId}
                AND COALESCE(admin_approval_note, '') NOT IN (
                    ${DELETED_BY_ADMIN},
                    ${DELETED_BY_SUPPLIER},
                    ${LEGACY_DELETED_NOTE}
                )
                RETURNING id, product_id
            `;

        if (!result.length) {
            return false;
        }

        await sql`
            UPDATE products
            SET
                is_active = FALSE,
                updated_at = NOW()
            WHERE id = ${result[0].product_id}
            AND NOT EXISTS (
                SELECT 1
                FROM supplier_products other_sp
                WHERE other_sp.product_id = products.id
                AND other_sp.id <> ${result[0].id}
                AND other_sp.approval_status = 'approved'
                AND COALESCE(other_sp.admin_approval_note, '') NOT IN (
                    ${DELETED_BY_ADMIN},
                    ${DELETED_BY_SUPPLIER},
                    ${LEGACY_DELETED_NOTE}
                )
            )
        `;

        clearPublicCache();

        return true;
    }

    // =========================================================
    // ADMIN: DELETE SUPPLIER PRODUCT
    // =========================================================

    router.delete("/supplier-products/:id", requireAdmin, async (req, res) => {
        try {
            if (!validId(req.params.id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid supplier product ID."
                });
            }

            const deleted = await safelyDeleteSupplierProduct(
                req.params.id,
                DELETED_BY_ADMIN
            );

            if (!deleted) {
                return res.status(404).json({
                    success: false,
                    message: "Supplier product not found or already deleted."
                });
            }

            return res.json({
                success: true,
                message: "Supplier product deleted successfully."
            });
        } catch (error) {
            console.error("Admin delete supplier product error:", error);

            return res.status(500).json({
                success: false,
                message: "Could not delete supplier product."
            });
        }
    });

    // =========================================================
    // SUPPLIER: GET OWN NON-DELETED PRODUCTS
    // =========================================================

    router.get("/supplier/my-products", requireSupplier, async (req, res) => {
        try {
            const records = await sql`
                SELECT
                    sp.id,
                    sp.product_id,
                    sp.supplier_cost AS purchase_price,
                    sp.selling_price,
                    sp.delivery_cost,
                    sp.other_cost,
                    sp.stock_available AS supplier_stock_quantity,
                    sp.sku AS supplier_sku,
                    sp.proposed_selling_price,
                    sp.approval_status,
                    sp.admin_approval_note,
                    sp.created_at,
                    p.name AS product_name,
                    p.description,
                    p.image_url,
                    p.price AS public_selling_price,
                    NULL::text AS category,
                    NULL::text AS notes,
                    TRUE AS is_available,
                    p.is_active AS is_active
                FROM supplier_products sp
                JOIN products p ON p.id = sp.product_id
                WHERE sp.supplier_id = ${req.supplier.id}
                AND COALESCE(sp.admin_approval_note, '') NOT IN (
                    ${DELETED_BY_ADMIN},
                    ${DELETED_BY_SUPPLIER},
                    ${LEGACY_DELETED_NOTE}
                )
                ORDER BY sp.id DESC
            `;

            res.setHeader("Cache-Control", "no-store");

            return res.json({
                success: true,
                products: records
            });
        } catch (error) {
            console.error("Supplier own products error:", error);

            return res.status(500).json({
                success: false,
                message: "Could not load your products."
            });
        }
    });

    // =========================================================
    // SUPPLIER: DELETE OWN PRODUCT
    // =========================================================

    router.delete("/supplier/my-products/:id", requireSupplier, async (req, res) => {
        try {
            if (!validId(req.params.id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid product ID."
                });
            }

            const deleted = await safelyDeleteSupplierProduct(
                req.params.id,
                DELETED_BY_SUPPLIER,
                req.supplier.id
            );

            if (!deleted) {
                return res.status(404).json({
                    success: false,
                    message: "Product not found or you do not have permission to delete it."
                });
            }

            return res.json({
                success: true,
                message: "Your product has been deleted successfully."
            });
        } catch (error) {
            console.error("Supplier delete product error:", error);

            return res.status(500).json({
                success: false,
                message: "Could not delete your product."
            });
        }
    });

    // =========================================================
    // SUPPLIER: ADD NEW PRODUCT
    // =========================================================

    router.post("/supplier/my-products", requireSupplier, async (req, res) => {
        try {
            const validation = validateSupplierProduct(req.body);

            if (validation.error) {
                return res.status(400).json({
                    success: false,
                    message: validation.error
                });
            }

            const d = validation.data;

            const result = await sql`
                WITH new_product AS (
                    INSERT INTO products (
                        name, description, price,
                        stock_quantity, image_url, is_active
                    )
                    VALUES (
                        ${d.name},
                        ${d.description || null},
                        ${d.proposedPrice},
                        ${d.stock},
                        ${d.imageUrl},
                        FALSE
                    )
                    RETURNING id
                ),
                new_supplier_product AS (
                    INSERT INTO supplier_products (
                        supplier_id, product_id, supplier_cost,
                        selling_price, delivery_cost, other_cost,
                        stock_available, sku, proposed_selling_price,
                        approval_status, bazar_ghor_profit_percentage
                    )
                    SELECT
                        ${req.supplier.id},
                        id,
                        ${d.purchasePrice},
                        ${d.proposedPrice},
                        ${d.deliveryCost},
                        ${d.otherCost},
                        ${d.stock},
                        ${d.sku || null},
                        ${d.proposedPrice},
                        'pending',
                        0
                    FROM new_product
                    RETURNING id, product_id
                )
                SELECT id, product_id
                FROM new_supplier_product
            `;

            return res.status(201).json({
                success: true,
                message: "Product submitted. Waiting for Admin approval.",
                id: result[0].id,
                product_id: result[0].product_id
            });
        } catch (error) {
            console.error("Supplier add product error:", error);

            return res.status(500).json({
                success: false,
                message: "Could not submit your product."
            });
        }
    });

    // =========================================================
    // SUPPLIER: UPDATE OWN PRODUCT
    // =========================================================

    router.put("/supplier/my-products/:id", requireSupplier, async (req, res) => {
        try {
            if (!validId(req.params.id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid product ID."
                });
            }

            const validation = validateSupplierProduct(req.body);

            if (validation.error) {
                return res.status(400).json({
                    success: false,
                    message: validation.error
                });
            }

            const d = validation.data;

            const result = await sql`
                WITH updated_link AS (
                    UPDATE supplier_products sp
                    SET
                        supplier_cost = ${d.purchasePrice},
                        selling_price = ${d.proposedPrice},
                        delivery_cost = ${d.deliveryCost},
                        other_cost = ${d.otherCost},
                        stock_available = ${d.stock},
                        sku = ${d.sku || null},
                        proposed_selling_price = ${d.proposedPrice},
                        approval_status = 'pending',
                        admin_approval_note = NULL,
                        updated_at = NOW()
                    WHERE sp.id = ${req.params.id}
                    AND sp.supplier_id = ${req.supplier.id}
                    AND COALESCE(sp.admin_approval_note, '') NOT IN (
                        ${DELETED_BY_ADMIN},
                        ${DELETED_BY_SUPPLIER},
                        ${LEGACY_DELETED_NOTE}
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM supplier_products other_sp
                        WHERE other_sp.product_id = sp.product_id
                        AND other_sp.supplier_id <> sp.supplier_id
                        AND COALESCE(
                            other_sp.admin_approval_note, ''
                        ) NOT IN (
                            ${DELETED_BY_ADMIN},
                            ${DELETED_BY_SUPPLIER},
                            ${LEGACY_DELETED_NOTE}
                        )
                    )
                    RETURNING sp.id, sp.product_id
                ),
                updated_product AS (
                    UPDATE products p
                    SET
                        name = ${d.name},
                        description = ${d.description || null},
                        price = ${d.proposedPrice},
                        stock_quantity = ${d.stock},
                        image_url = ${d.imageUrl},
                        is_active = FALSE,
                        updated_at = NOW()
                    FROM updated_link ul
                    WHERE p.id = ul.product_id
                    RETURNING p.id
                )
                SELECT ul.id
                FROM updated_link ul
                JOIN updated_product up ON up.id = ul.product_id
            `;

            if (!result.length) {
                return res.status(404).json({
                    success: false,
                    message: "Product not found, or it is linked to another supplier."
                });
            }

            clearPublicCache();

            return res.json({
                success: true,
                message: "Product updated and sent for Admin approval."
            });
        } catch (error) {
            console.error("Supplier update product error:", error);

            return res.status(500).json({
                success: false,
                message: "Could not update your product."
            });
        }
    });

    // =========================================================
    // ADMIN: GET APPROVED SUPPLIERS FOR AN ORDER ITEM
    // =========================================================

    router.get(
        "/orders/:orderId/items/:itemId/supplier-options",
        requireAdmin,
        async (req, res) => {
            try {
                const { orderId, itemId } = req.params;

                if (!validId(orderId) || !validId(itemId)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid order or item ID."
                    });
                }

                const items = await sql`
                    SELECT id, product_id, product_name, quantity
                    FROM order_items
                    WHERE id = ${itemId}
                    AND order_id = ${orderId}
                    LIMIT 1
                `;

                if (!items.length) {
                    return res.status(404).json({
                        success: false,
                        message: "Order item not found."
                    });
                }

                const item = items[0];

                const suppliers = await sql`
                    SELECT
                        sp.id AS supplier_product_id,
                        sp.supplier_id,
                        s.supplier_name,
                        s.business_name,
                        sp.stock_available,
                        sp.selling_price,
                        sp.supplier_cost
                    FROM supplier_products sp
                    JOIN suppliers s ON s.id = sp.supplier_id
                    WHERE sp.product_id = ${item.product_id}
                    AND s.status = 'active'
                    AND sp.approval_status = 'approved'
                    AND sp.is_active = TRUE
                    AND sp.is_available = TRUE
                    AND COALESCE(sp.admin_approval_note, '') NOT IN (
                        ${DELETED_BY_ADMIN},
                        ${DELETED_BY_SUPPLIER},
                        ${LEGACY_DELETED_NOTE}
                    )
                    ORDER BY sp.stock_available DESC, s.supplier_name ASC
                `;

                res.setHeader("Cache-Control", "no-store");

                return res.json({
                    success: true,
                    item: {
                        id: item.id,
                        product_id: item.product_id,
                        product_name: item.product_name,
                        quantity: item.quantity
                    },
                    suppliers
                });
            } catch (error) {
                console.error("Supplier options error:", error);

                return res.status(500).json({
                    success: false,
                    message: "Could not load supplier options."
                });
            }
        }
    );

    // =========================================================
    // ADMIN: SEND ONE ORDER ITEM TO A SELECTED SUPPLIER
    // =========================================================

    router.post(
        "/orders/:orderId/items/:itemId/handoff",
        requireAdmin,
        async (req, res) => {
            try {
                const { orderId, itemId } = req.params;
                const supplierProductId = req.body?.supplier_product_id;

                if (
                    !validId(orderId) ||
                    !validId(itemId) ||
                    !validId(supplierProductId)
                ) {
                    return res.status(400).json({
                        success: false,
                        message: "Please select a valid order item and supplier."
                    });
                }

                const orderItems = await sql`
                    SELECT
                        oi.id,
                        oi.product_id,
                        oi.quantity,
                        o.status AS order_status
                    FROM order_items oi
                    JOIN orders o ON o.id = oi.order_id
                    WHERE oi.id = ${itemId}
                    AND oi.order_id = ${orderId}
                    LIMIT 1
                `;

                if (!orderItems.length) {
                    return res.status(404).json({
                        success: false,
                        message: "Order item not found."
                    });
                }

                if (
                    String(orderItems[0].order_status).toLowerCase() === "cancelled"
                ) {
                    return res.status(400).json({
                        success: false,
                        message: "A cancelled order cannot be sent to a supplier."
                    });
                }

                const selectedSupplierProducts = await sql`
                    SELECT
                        sp.id,
                        sp.supplier_id,
                        sp.product_id,
                        s.supplier_name
                    FROM supplier_products sp
                    JOIN suppliers s ON s.id = sp.supplier_id
                    WHERE sp.id = ${supplierProductId}
                    AND sp.product_id = ${orderItems[0].product_id}
                    AND s.status = 'active'
                    AND sp.approval_status = 'approved'
                    AND sp.is_active = TRUE
                    AND sp.is_available = TRUE
                    AND COALESCE(sp.admin_approval_note, '') NOT IN (
                        ${DELETED_BY_ADMIN},
                        ${DELETED_BY_SUPPLIER},
                        ${LEGACY_DELETED_NOTE}
                    )
                    LIMIT 1
                `;

                if (!selectedSupplierProducts.length) {
                    return res.status(400).json({
                        success: false,
                        message: "Selected supplier is not approved or is not linked to this product."
                    });
                }

                const selected = selectedSupplierProducts[0];

                const existing = await sql`
                    SELECT id, status
                    FROM supplier_order_handoffs
                    WHERE order_item_id = ${itemId}
                    LIMIT 1
                `;

                if (existing.length) {
                    return res.status(409).json({
                        success: false,
                        message: "This order item has already been sent to a supplier.",
                        handoff_status: existing[0].status
                    });
                }

                const result = await sql`
                    INSERT INTO supplier_order_handoffs (
                        order_id,
                        order_item_id,
                        supplier_id,
                        supplier_product_id,
                        status,
                        sent_at,
                        updated_at
                    )
                    VALUES (
                        ${orderId},
                        ${itemId},
                        ${selected.supplier_id},
                        ${selected.id},
                        'sent',
                        NOW(),
                        NOW()
                    )
                    RETURNING id, status, sent_at
                `;

                return res.status(201).json({
                    success: true,
                    message: "Order item sent to supplier successfully.",
                    handoff: result[0]
                });
            } catch (error) {
                console.error("Send order to supplier error:", error);

                if (error.code === "23505") {
                    return res.status(409).json({
                        success: false,
                        message: "This order item has already been assigned to a supplier."
                    });
                }

                return res.status(500).json({
                    success: false,
                    message: "Could not send order item to supplier."
                });
            }
        }
    );

    // =========================================================
    // ADMIN: VIEW ALL SUPPLIER ORDER HANDOFFS
    // Requires migration 003_supplier_delivery_progress.sql
    // =========================================================

    router.get(
        "/supplier-order-handoffs",
        requireAdmin,
        async (req, res) => {
            try {
                const records = await sql`
                    SELECT
                        h.id,
                        h.order_id,
                        h.order_item_id,
                        h.supplier_id,
                        h.supplier_product_id,
                        h.status,
                        h.supplier_response_note,
                        h.admin_note,
                        h.sent_at,
                        h.responded_at,
                        h.reviewed_at,
                        h.delivery_status,
                        h.delivery_note,
                        h.delivery_updated_at,
                        o.order_number,
                        o.status AS order_status,
                        oi.product_name,
                        oi.quantity,
                        oi.unit_price,
                        oi.subtotal,
                        s.supplier_name,
                        s.business_name
                    FROM supplier_order_handoffs h
                    JOIN orders o ON o.id = h.order_id
                    JOIN order_items oi ON oi.id = h.order_item_id
                    JOIN suppliers s ON s.id = h.supplier_id
                    ORDER BY h.id DESC
                `;

                res.setHeader("Cache-Control", "no-store");

                return res.json({
                    success: true,
                    handoffs: records
                });
            } catch (error) {
                console.error("Admin handoff list error:", error);

                return res.status(500).json({
                    success: false,
                    message: "Could not load supplier order handoffs."
                });
            }
        }
    );

    // =========================================================
    // SUPPLIER: VIEW ONLY ORDERS ASSIGNED TO THIS SUPPLIER
    // Customer details are revealed only after supplier accepts.
    // =========================================================

    router.get(
        "/supplier/orders",
        requireSupplier,
        async (req, res) => {
            try {
                const records = await sql`
                    SELECT
                        h.id AS id,
                        h.id AS handoff_id,
                        h.order_id,
                        h.order_item_id,
                        h.status AS status,
                        h.status AS handoff_status,
                        h.supplier_response_note,
                        h.sent_at,
                        h.responded_at,
                        h.reviewed_at,
                        h.delivery_status,
                        h.delivery_note,
                        h.delivery_updated_at,
                        o.order_number,
                        o.created_at AS order_created_at,
                        oi.product_name,
                        oi.quantity,
                        oi.unit_price,
                        oi.subtotal,

                        CASE
                            WHEN h.status IN ('accepted', 'admin_approved')
                            THEN c.name
                            ELSE NULL
                        END AS customer_name,

                        CASE
                            WHEN h.status IN ('accepted', 'admin_approved')
                            THEN c.phone
                            ELSE NULL
                        END AS customer_phone,

                        CASE
                            WHEN h.status IN ('accepted', 'admin_approved')
                            THEN o.delivery_address
                            ELSE NULL
                        END AS delivery_address

                    FROM supplier_order_handoffs h
                    JOIN orders o ON o.id = h.order_id
                    JOIN order_items oi ON oi.id = h.order_item_id
                    LEFT JOIN customers c ON c.id = o.customer_id

                    WHERE h.supplier_id = ${req.supplier.id}
                    ORDER BY h.sent_at DESC, h.id DESC
                `;

                res.setHeader("Cache-Control", "no-store");

                return res.json({
                    success: true,
                    orders: records
                });
            } catch (error) {
                console.error("Supplier order list error:", error);

                return res.status(500).json({
                    success: false,
                    message: "Could not load your received orders."
                });
            }
        }
    );

    // =========================================================
    // SUPPLIER: ACCEPT OR REJECT AN ASSIGNED ORDER ITEM
    // =========================================================

    router.patch(
        "/supplier/orders/:handoffId/response",
        requireSupplier,
        async (req, res) => {
            try {
                const { handoffId } = req.params;

                if (!validId(handoffId)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid order reference."
                    });
                }

                const decision = String(
                    req.body?.decision || ""
                ).trim().toLowerCase();

                const note = String(
                    req.body?.note || ""
                ).trim().slice(0, 3000);

                if (!["accepted", "rejected"].includes(decision)) {
                    return res.status(400).json({
                        success: false,
                        message: "Please choose Accept or Reject."
                    });
                }

                if (decision === "rejected" && !note) {
                    return res.status(400).json({
                        success: false,
                        message: "Please provide a reason for rejecting this order."
                    });
                }

                const result = await sql`
                    UPDATE supplier_order_handoffs
                    SET
                        status = ${decision},
                        supplier_response_note = ${note || null},
                        responded_at = NOW(),
                        updated_at = NOW()
                    WHERE id = ${handoffId}
                    AND supplier_id = ${req.supplier.id}
                    AND status = 'sent'
                    RETURNING
                        id, status, supplier_response_note, responded_at
                `;

                if (!result.length) {
                    const existing = await sql`
                        SELECT id, status
                        FROM supplier_order_handoffs
                        WHERE id = ${handoffId}
                        AND supplier_id = ${req.supplier.id}
                        LIMIT 1
                    `;

                    if (!existing.length) {
                        return res.status(404).json({
                            success: false,
                            message: "Order not found in your supplier account."
                        });
                    }

                    return res.status(409).json({
                        success: false,
                        message: "You have already responded to this order or it has been reviewed by Admin.",
                        handoff_status: existing[0].status
                    });
                }

                return res.json({
                    success: true,
                    message: decision === "accepted"
                        ? "Order accepted. Customer delivery details are now available."
                        : "Order rejected. Admin has been notified.",
                    handoff: result[0]
                });
            } catch (error) {
                console.error("Supplier order response error:", error);

                return res.status(500).json({
                    success: false,
                    message: "Could not submit your order response."
                });
            }
        }
    );

    // =========================================================
    // ADMIN: FINAL REVIEW OF SUPPLIER RESPONSE
    // =========================================================

    router.patch(
        "/supplier-order-handoffs/:id/review",
        requireAdmin,
        async (req, res) => {
            try {
                const { id } = req.params;

                if (!validId(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid handoff ID."
                    });
                }

                const decision = String(
                    req.body?.decision || ""
                ).trim().toLowerCase();

                const note = String(
                    req.body?.note || ""
                ).trim().slice(0, 3000);

                if (!["approved", "rejected"].includes(decision)) {
                    return res.status(400).json({
                        success: false,
                        message: "Decision must be approved or rejected."
                    });
                }

                const requiredSupplierStatus =
                    decision === "approved" ? "accepted" : "rejected";

                const finalStatus =
                    decision === "approved"
                        ? "admin_approved"
                        : "admin_rejected";

                const result = await sql`
                    UPDATE supplier_order_handoffs
                    SET
                        status = ${finalStatus},
                        admin_note = ${note || null},
                        reviewed_at = NOW(),
                        updated_at = NOW()
                    WHERE id = ${id}
                    AND status = ${requiredSupplierStatus}
                    RETURNING id, status, admin_note, reviewed_at
                `;

                if (!result.length) {
                    return res.status(409).json({
                        success: false,
                        message: "This supplier response is not available for final review. Check its current status."
                    });
                }

                return res.json({
                    success: true,
                    message: decision === "approved"
                        ? "Supplier response approved by Admin."
                        : "Supplier response rejected by Admin.",
                    handoff: result[0]
                });
            } catch (error) {
                console.error("Admin handoff review error:", error);

                return res.status(500).json({
                    success: false,
                    message: "Could not review supplier response."
                });
            }
        }
    );

    // =========================================================
    // SUPPLIER: UPDATE DELIVERY PROGRESS
    // Only Admin-approved supplier orders can be updated.
    // Requires migration 003_supplier_delivery_progress.sql
    // =========================================================

    router.patch(
        "/supplier/orders/:handoffId/delivery",
        requireSupplier,
        async (req, res) => {
            try {
                const { handoffId } = req.params;

                if (!validId(handoffId)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid order reference."
                    });
                }

                const deliveryStatus = String(
                    req.body?.delivery_status || ""
                ).trim().toLowerCase();

                const deliveryNote = String(
                    req.body?.delivery_note || ""
                ).trim().slice(0, 2000);

                if (!DELIVERY_STATUSES.includes(deliveryStatus)) {
                    return res.status(400).json({
                        success: false,
                        message: "Please select a valid delivery status."
                    });
                }

                const result = await sql`
                    UPDATE supplier_order_handoffs
                    SET
                        delivery_status = ${deliveryStatus},
                        delivery_note = ${deliveryNote || null},
                        delivery_updated_at = NOW(),
                        updated_at = NOW()
                    WHERE id = ${handoffId}
                    AND supplier_id = ${req.supplier.id}
                    AND status = 'admin_approved'
                    AND (
                        CASE delivery_status
                            WHEN 'not_started' THEN 0
                            WHEN 'preparing' THEN 1
                            WHEN 'ready_for_dispatch' THEN 2
                            WHEN 'shipped' THEN 3
                            WHEN 'delivered' THEN 4
                            ELSE -1
                        END
                    ) <= (
                        CASE ${deliveryStatus}
                            WHEN 'preparing' THEN 1
                            WHEN 'ready_for_dispatch' THEN 2
                            WHEN 'shipped' THEN 3
                            WHEN 'delivered' THEN 4
                            ELSE -1
                        END
                    )
                    RETURNING
                        id,
                        status,
                        delivery_status,
                        delivery_note,
                        delivery_updated_at
                `;

                if (!result.length) {
                    const existing = await sql`
                        SELECT id, status, delivery_status
                        FROM supplier_order_handoffs
                        WHERE id = ${handoffId}
                        AND supplier_id = ${req.supplier.id}
                        LIMIT 1
                    `;

                    if (!existing.length) {
                        return res.status(404).json({
                            success: false,
                            message: "Order not found in your supplier account."
                        });
                    }

                    if (existing[0].status !== "admin_approved") {
                        return res.status(403).json({
                            success: false,
                            message: "Admin must approve this supplier order before delivery updates."
                        });
                    }

                    return res.status(400).json({
                        success: false,
                        message: "Delivery progress cannot move backwards."
                    });
                }

                return res.json({
                    success: true,
                    message: "Delivery progress updated successfully.",
                    handoff: result[0]
                });
            } catch (error) {
                console.error("Supplier delivery update error:", error);

                return res.status(500).json({
                    success: false,
                    message: "Could not update delivery progress."
                });
            }
        }
    );

    return router;
}

module.exports = createSupplierProductsRouter;
