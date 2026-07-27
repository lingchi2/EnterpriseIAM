package com.enterpriseiam.identity.domain;

/** Account lifecycle is independent of roles and of authenticated session state. */
public enum UserStatus {
    PENDING_VERIFICATION,
    ACTIVE,
    LOCKED,
    DISABLED
}
