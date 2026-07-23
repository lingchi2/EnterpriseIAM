-- Flyway runs this migration in the configured "iam" schema.
-- PostgreSQL owns referential integrity; application aggregates never cascade
-- deletion into shared roles or permissions. No default accounts are seeded.

CREATE TABLE users (
    id              UUID         PRIMARY KEY,
    email           VARCHAR(254) NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    status          VARCHAR(32)  NOT NULL DEFAULT 'PENDING_VERIFICATION',
    department      VARCHAR(100) NOT NULL,
    clearance_level SMALLINT     NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version         BIGINT       NOT NULL DEFAULT 0,

    CONSTRAINT uk_users_email UNIQUE (email),
    CONSTRAINT ck_users_email_canonical CHECK (
        email = lower(btrim(email))
        AND email ~ '^[^[:space:]@]+@[^[:space:]@]+$'
    ),
    -- Compatible with Spring's DelegatingPasswordEncoder; plaintext {noop}
    -- encodings are explicitly forbidden. The password service chooses a
    -- vetted adaptive password encoder and its work factor in STEP 2.
    CONSTRAINT ck_users_password_hash_encoded CHECK (
        password_hash ~ '^\{[A-Za-z0-9@._-]+\}[^[:space:]]+$'
        AND password_hash NOT LIKE '{noop}%'
    ),
    CONSTRAINT ck_users_status CHECK (
        status IN ('PENDING_VERIFICATION', 'ACTIVE', 'LOCKED', 'DISABLED')
    ),
    CONSTRAINT ck_users_department CHECK (
        department = btrim(department) AND department <> ''
    ),
    CONSTRAINT ck_users_clearance_level CHECK (clearance_level BETWEEN 0 AND 4),
    CONSTRAINT ck_users_version CHECK (version >= 0)
);

CREATE TABLE roles (
    id         UUID        PRIMARY KEY,
    name       VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version    BIGINT      NOT NULL DEFAULT 0,

    CONSTRAINT uk_roles_name UNIQUE (name),
    CONSTRAINT ck_roles_name CHECK (name ~ '^[A-Z][A-Z0-9_]*$'),
    CONSTRAINT ck_roles_version CHECK (version >= 0)
);

CREATE TABLE permissions (
    id         UUID         PRIMARY KEY,
    name       VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version    BIGINT       NOT NULL DEFAULT 0,

    CONSTRAINT uk_permissions_name UNIQUE (name),
    CONSTRAINT ck_permissions_name CHECK (
        name ~ '^[A-Z][A-Z0-9_]*(:[A-Z][A-Z0-9_]*)*$'
    ),
    CONSTRAINT ck_permissions_version CHECK (version >= 0)
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,

    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT
);

-- The primary key serves user -> roles; this serves reverse membership lookups
-- and PostgreSQL's referential check when a referenced role is deleted.
CREATE INDEX ix_user_roles_role_user ON user_roles (role_id, user_id);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL,
    permission_id UUID NOT NULL,

    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_permissions_role
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT,
    CONSTRAINT fk_role_permissions_permission
        FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE RESTRICT
);

CREATE INDEX ix_role_permissions_permission_role
    ON role_permissions (permission_id, role_id);

CREATE TABLE refresh_tokens (
    id                   UUID        PRIMARY KEY,
    user_id              UUID        NOT NULL,
    -- Persist only the SHA-256 digest of a cryptographically random token.
    -- A token's plaintext is returned once to the client, never persisted.
    token_hash           VARCHAR(64) NOT NULL,
    family_id            UUID        NOT NULL,
    expires_at           TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked              BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at           TIMESTAMPTZ,
    replaced_by_token_id UUID,
    version              BIGINT      NOT NULL DEFAULT 0,

    CONSTRAINT uk_refresh_tokens_hash UNIQUE (token_hash),
    -- PostgreSQL requires an exact unique target for the composite self-FK.
    CONSTRAINT uk_refresh_tokens_identity_family UNIQUE (id, user_id, family_id),
    CONSTRAINT fk_refresh_tokens_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT ck_refresh_tokens_hash CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_refresh_tokens_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_refresh_tokens_revocation CHECK (
        (revoked AND revoked_at IS NOT NULL AND revoked_at >= created_at)
        OR (NOT revoked AND revoked_at IS NULL)
    ),
    CONSTRAINT ck_refresh_tokens_replacement CHECK (
        replaced_by_token_id IS NULL
        OR (revoked AND replaced_by_token_id <> id)
    ),
    CONSTRAINT ck_refresh_tokens_version CHECK (version >= 0),
    -- Rotation cannot point into another user's session or another family.
    -- NO ACTION permits deleting a user's entire token graph in one statement.
    CONSTRAINT fk_refresh_tokens_replacement
        FOREIGN KEY (replaced_by_token_id, user_id, family_id)
        REFERENCES refresh_tokens (id, user_id, family_id)
        ON DELETE NO ACTION
        DEFERRABLE INITIALLY IMMEDIATE
);

-- Session history and user-wide revocation; also supports user FK deletion.
CREATE INDEX ix_refresh_tokens_user_created
    ON refresh_tokens (user_id, created_at DESC);

-- A replay response revokes every still-live token in the compromised family.
CREATE INDEX ix_refresh_tokens_active_family
    ON refresh_tokens (family_id, user_id) WHERE NOT revoked;

-- Expiration/retention cleanup; do not purge replay evidence before policy allows.
CREATE INDEX ix_refresh_tokens_expires_at ON refresh_tokens (expires_at);

-- Supports the replacement FK check when a successor is deleted.
CREATE INDEX ix_refresh_tokens_replacement
    ON refresh_tokens (replaced_by_token_id, user_id, family_id)
    WHERE replaced_by_token_id IS NOT NULL;
