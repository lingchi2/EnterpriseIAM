package com.enterpriseiam.api.auth;

import java.time.Instant;

/** Absolute UTC expiration instants avoid clock-sensitive expires-in calculations at serialization. */
public record TokenResponse(String tokenType, String accessToken, String refreshToken,
        Instant accessTokenExpiresAt, Instant refreshTokenExpiresAt) {
    @Override
    public String toString() {
        return "TokenResponse[tokenType=Bearer, accessToken=[REDACTED], refreshToken=[REDACTED]]";
    }
}
