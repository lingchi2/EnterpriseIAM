-- Row locks acquired by the ABAC resolver remain held until the protected operation commits.
-- The service never accepts owner/department/classification metadata from the caller.
CREATE TABLE secured_resources (
    id             UUID         PRIMARY KEY,
    owner_id       UUID         NOT NULL,
    department     VARCHAR(100) NOT NULL,
    classification SMALLINT     NOT NULL,
    content        TEXT         NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version        BIGINT       NOT NULL DEFAULT 0,

    CONSTRAINT fk_secured_resources_owner
        FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT ck_secured_resources_department CHECK (
        department = btrim(department) AND department <> ''
    ),
    CONSTRAINT ck_secured_resources_classification CHECK (classification BETWEEN 0 AND 4),
    CONSTRAINT ck_secured_resources_content CHECK (char_length(content) <= 1048576),
    CONSTRAINT ck_secured_resources_version CHECK (version >= 0)
);

CREATE INDEX ix_secured_resources_owner ON secured_resources (owner_id);
CREATE INDEX ix_secured_resources_department ON secured_resources (department, id);
