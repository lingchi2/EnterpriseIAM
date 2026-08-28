package com.enterpriseiam.security.ratelimit;

public record RateLimitDecision(boolean allowed, long retryAfterSeconds) {
    public RateLimitDecision {
        if ((allowed && retryAfterSeconds != 0) || (!allowed && retryAfterSeconds < 1)) {
            throw new IllegalArgumentException("Invalid authentication rate-limit decision");
        }
    }
}
