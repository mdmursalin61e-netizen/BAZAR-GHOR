
-- BAZAR GHOR
-- Migration 004: Customer Accounts
-- Preserve all existing customers and orders.

BEGIN;

ALTER TABLE customers
ADD COLUMN IF NOT EXISTS password_hash TEXT;

ALTER TABLE customers
ADD COLUMN IF NOT EXISTS account_status VARCHAR(20)
DEFAULT 'active';

ALTER TABLE customers
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ
DEFAULT NOW();

UPDATE customers
SET account_status = 'active'
WHERE account_status IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'customers_account_status_check'
          AND conrelid = 'customers'::regclass
    ) THEN
        ALTER TABLE customers
        ADD CONSTRAINT customers_account_status_check
        CHECK (account_status IN ('active', 'inactive', 'blocked'));
    END IF;
END $$;

-- Unique phone numbers for registered accounts only.
CREATE UNIQUE INDEX IF NOT EXISTS
idx_customers_unique_account_phone
ON customers (
    REGEXP_REPLACE(phone, '[^0-9]', '', 'g')
)
WHERE password_hash IS NOT NULL
  AND phone IS NOT NULL
  AND TRIM(phone) <> ''
  AND REGEXP_REPLACE(phone, '[^0-9]', '', 'g') <> '';

-- Unique email addresses for registered accounts only.
CREATE UNIQUE INDEX IF NOT EXISTS
idx_customers_unique_account_email
ON customers (LOWER(TRIM(email)))
WHERE password_hash IS NOT NULL
  AND email IS NOT NULL
  AND TRIM(email) <> '';

COMMIT;
