package com.enterpriseiam.audit.model;

/** STARTED and one terminal event are independent, append-only documents. */
public enum AuditPhase {
    STARTED,
    SUCCEEDED,
    FAILED
}
