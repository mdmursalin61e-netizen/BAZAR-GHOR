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

COMMENT ON COLUMN supplier_order_handoffs.delivery_status IS 'BAZAR GHOR supplier fulfillment stage: not_started, preparing, ready_for_dispatch, shipped, delivered';
COMMENT ON COLUMN supplier_order_handoffs.delivery_note IS 'BAZAR GHOR supplier handoff or dispatch note';
COMMENT ON COLUMN supplier_order_handoffs.delivery_updated_at IS 'Timestamp of last supplier delivery progress update';

UPDATE supplier_order_handoffs
SET delivery_status = 'not_started'
WHERE delivery_status IS NULL
   OR delivery_status NOT IN (
       'not_started',
       'preparing',
       'ready_for_dispatch',
       'shipped',
       'delivered'
   );

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE c.conname = 'supplier_handoffs_delivery_status_check'
          AND t.relname = 'supplier_order_handoffs'
          AND n.nspname = 'public'
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