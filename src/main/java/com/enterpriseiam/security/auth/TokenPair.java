package com.enterpriseiam.security.auth;

import java.time.Instant;

/** Internal issuance result; the API mapper owns the HTTP representation. */
public record TokenPair(String accessToken, String refreshToken,
        Instant accessTokenExpiresAt, Instant refreshTokenExpiresAt) {
    @Override
    public String toString() {
        return "TokenPair[accessToken=[REDACTED], refreshToken=[REDACTED]]";
    }
}
