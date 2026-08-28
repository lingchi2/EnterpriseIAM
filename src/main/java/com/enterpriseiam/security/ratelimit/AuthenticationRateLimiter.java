package com.enterpriseiam.security.ratelimit;

public interface AuthenticationRateLimiter {
    RateLimitDecision check(String remoteAddress, String endpoint);
}
