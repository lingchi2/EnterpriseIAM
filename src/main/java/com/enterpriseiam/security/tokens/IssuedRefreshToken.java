package com.enterpriseiam.security.tokens;

import java.time.Instant;
import java.util.UUID;

/** Sensitive value: transport once over TLS; never persist or log the plaintext. */
public record IssuedRefreshToken(String rawToken, UUID userId, UUID sessionId, Instant expiresAt) {

    @Override
    public String toString() {
        return "IssuedRefreshToken[rawToken=[REDACTED], userId=" + userId
                + ", sessionId=" + sessionId + ", expiresAt=" + expiresAt + "]";
    }
}
