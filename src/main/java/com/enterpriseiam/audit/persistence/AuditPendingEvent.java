package com.enterpriseiam.audit.persistence;

/** Contains no audit data; only a hint to drain the durable outbox after commit. */
public record AuditPendingEvent() { }
