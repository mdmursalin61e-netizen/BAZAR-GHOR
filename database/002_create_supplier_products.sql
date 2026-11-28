CREATE TABLE IF NOT EXISTS supplier_products (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    supplier_id BIGINT NOT NULL
        REFERENCES suppliers(id) ON DELETE RESTRICT,

    product_id BIGINT NOT NULL
        REFERENCES products(id) ON DELETE RESTRICT,

    supplier_cost NUMERIC(12, 2) NOT NULL DEFAULT 0
        CHECK (supplier_cost >= 0),

    selling_price NUMERIC(12, 2) NOT NULL DEFAULT 0
        CHECK (selling_price >= 0),

    delivery_cost NUMERIC(12, 2) NOT NULL DEFAULT 0
        CHECK (delivery_cost >= 0),

    other_cost NUMERIC(12, 2) NOT NULL DEFAULT 0
        CHECK (other_cost >= 0),

    stock_available INTEGER NOT NULL DEFAULT 0
        CHECK (stock_available >= 0),

    sku VARCHAR(100),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (supplier_id, product_id)
);

COMMENT ON TABLE supplier_products IS 'BAZAR GHOR supplier product pricing, cost breakdown, SKU, and stock mapping';

CREATE INDEX IF NOT EXISTS idx_supplier_products_supplier
ON supplier_products(supplier_id);

CREATE INDEX IF NOT EXISTS idx_supplier_products_product
ON supplier_products(product_id);