-- The authoritative audit ledger is independent of mutable identity records.
-- Runtime roles must not own these tables or the trigger function. Restrict
-- audit_events to SELECT/INSERT and audit_delivery to SELECT/INSERT/UPDATE.
CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    payload JSONB NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    CONSTRAINT ck_audit_events_payload CHECK (
        jsonb_typeof(payload) = 'object' AND payload ->> 'id' IS NOT NULL
        AND payload ->> 'id' = id::text
    ),
    CONSTRAINT ck_audit_events_sha256 CHECK (payload_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX ix_audit_events_occurred ON audit_events (occurred_at, id);

CREATE TABLE audit_delivery (
    event_id UUID PRIMARY KEY REFERENCES audit_events(id) ON DELETE RESTRICT,
    attempts BIGINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_until TIMESTAMPTZ,
    lease_token UUID,
    delivered_at TIMESTAMPTZ,
    last_error_code VARCHAR(48),
    CONSTRAINT ck_audit_delivery_lease CHECK (
        (lease_until IS NULL) = (lease_token IS NULL)
    ),
    CONSTRAINT ck_audit_delivery_error_code CHECK (
        last_error_code IS NULL OR last_error_code ~ '^[A-Z_]+$'
    )
);

CREATE INDEX ix_audit_delivery_pending ON audit_delivery (next_attempt_at, event_id)
    WHERE delivered_at IS NULL;

CREATE FUNCTION reject_audit_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Audit ledger is append-only' USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();

CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_event_mutation();

REVOKE ALL ON audit_events, audit_delivery FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_audit_event_mutation() FROM PUBLIC;
