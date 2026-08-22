package com.enterpriseiam.security.redis;

import java.time.Instant;
import java.util.UUID;

public interface AccessTokenBlacklist {
    void revoke(UUID tokenId, Instant expiresAt);
    boolean isRevoked(UUID tokenId);
}
