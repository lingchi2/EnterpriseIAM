package com.enterpriseiam.security.jwt;

import java.time.Instant;
import java.util.UUID;

public record IssuedAccessToken(String token, UUID tokenId, Instant expiresAt) {
    @Override
    public String toString() {
        return "IssuedAccessToken[token=REDACTED, tokenId=" + tokenId + ", expiresAt=" + expiresAt + "]";
    }
}
