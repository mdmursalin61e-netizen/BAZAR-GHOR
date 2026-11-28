CREATE TABLE IF NOT EXISTS suppliers (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    supplier_name VARCHAR(150) NOT NULL,
    business_name VARCHAR(180),
    phone VARCHAR(30),
    whatsapp VARCHAR(30),
    address TEXT,
    district VARCHAR(100),
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'inactive')),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE suppliers IS 'BAZAR GHOR supplier directory and fulfillment partners';

CREATE INDEX IF NOT EXISTS idx_suppliers_status
ON suppliers(status);

CREATE INDEX IF NOT EXISTS idx_suppliers_name
ON suppliers(supplier_name);