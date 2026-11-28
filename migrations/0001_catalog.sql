-- Serialize startup migrations across replicas. The caller wraps this in a transaction.
SELECT pg_advisory_xact_lock(483729104);
CREATE TABLE IF NOT EXISTS authz_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    graph jsonb NOT NULL
);
INSERT INTO authz_state(singleton, graph)
VALUES (true, '{"parents":{},"grants":[]}') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS authz_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    principal text NOT NULL,
    action text NOT NULL,
    resource jsonb NOT NULL,
    decision boolean NOT NULL,
    policy_ids jsonb NOT NULL,
    reason text NOT NULL
);
CREATE OR REPLACE FUNCTION authz_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'authorization audit is append-only';
END $$;
DROP TRIGGER IF EXISTS authz_audit_append_only ON authz_audit;
CREATE TRIGGER authz_audit_append_only BEFORE UPDATE OR DELETE OR TRUNCATE
ON authz_audit FOR EACH STATEMENT EXECUTE FUNCTION authz_audit_append_only();
REVOKE UPDATE, DELETE, TRUNCATE ON authz_audit FROM PUBLIC;
