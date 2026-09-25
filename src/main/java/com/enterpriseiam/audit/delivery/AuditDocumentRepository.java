package com.enterpriseiam.audit.delivery;

/** A narrow append-only port deliberately exposing neither save, update nor delete. */
public interface AuditDocumentRepository {
    CreateResult createOnly(AuditDocument document);

    enum CreateResult { CREATED, ALREADY_PRESENT }
}
