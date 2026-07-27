-- A durable session is the revocation boundary for both refresh-token families
-- and access JWTs. Every access request checks this row; a revoked family cannot
-- continue using an already-issued JWT until that JWT's expiration.
CREATE TABLE auth_sessions (
    id         UUID        PRIMARY KEY,
    user_id    UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT uk_auth_sessions_identity_user UNIQUE (id, user_id),
    CONSTRAINT fk_auth_sessions_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT ck_auth_sessions_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_auth_sessions_revocation CHECK (
        revoked_at IS NULL OR revoked_at >= created_at
    )
);

-- V1 allowed the same family UUID for different users. Do not silently merge
-- those security boundaries during an upgrade: fail transactionally for repair.
DO $$
BEGIN
    IF EXISTS (
        SELECT family_id FROM refresh_tokens
        GROUP BY family_id HAVING count(DISTINCT user_id) > 1
    ) THEN
        RAISE EXCEPTION 'Refresh-token family IDs must belong to exactly one user before V2';
    END IF;
END
$$;

-- Preserve existing revocations. The earliest recorded expiration is a
-- conservative absolute deadline; migration must never extend a session.
INSERT INTO auth_sessions (id, user_id, created_at, expires_at, revoked_at)
SELECT family_id, user_id, min(created_at), min(expires_at),
       CASE WHEN bool_and(revoked) THEN max(revoked_at) ELSE NULL END
FROM refresh_tokens
GROUP BY family_id, user_id;

ALTER TABLE refresh_tokens ADD CONSTRAINT fk_refresh_tokens_session
    FOREIGN KEY (family_id, user_id) REFERENCES auth_sessions (id, user_id)
    ON DELETE CASCADE;

CREATE INDEX ix_auth_sessions_user ON auth_sessions (user_id);
CREATE INDEX ix_auth_sessions_expires_at ON auth_sessions (expires_at);

-- Historical token rows are replay evidence. Retain the whole family until its
-- absolute expiry and the configured operational retention window have passed.
