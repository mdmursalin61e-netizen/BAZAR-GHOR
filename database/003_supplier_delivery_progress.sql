
-- BAZAR GHOR
-- Supplier Delivery Progress Migration
-- Safe to run more than once.

ALTER TABLE supplier_order_handoffs
ADD COLUMN IF NOT EXISTS delivery_status
VARCHAR(30) NOT NULL DEFAULT 'not_started';

ALTER TABLE supplier_order_handoffs
ADD COLUMN IF NOT EXISTS delivery_note
TEXT;

ALTER TABLE supplier_order_handoffs
ADD COLUMN IF NOT EXISTS delivery_updated_at
TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'supplier_handoffs_delivery_status_check'
    ) THEN
        ALTER TABLE supplier_order_handoffs
        ADD CONSTRAINT supplier_handoffs_delivery_status_check
        CHECK (
            delivery_status IN (
                'not_started',
                'preparing',
                'ready_for_dispatch',
                'shipped',
                'delivered'
            )
        );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS
idx_supplier_handoffs_delivery_status
ON supplier_order_handoffs (delivery_status);


