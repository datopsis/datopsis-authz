-- Same startup transaction and advisory lock as the catalog migration.
ALTER TABLE authz_audit ADD COLUMN IF NOT EXISTS result jsonb;
