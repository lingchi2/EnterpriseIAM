package com.enterpriseiam.security.ratelimit;

import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("iam.auth.rate-limit")
public record AuthenticationRateLimitProperties(@DefaultValue("20") int limit,
        @DefaultValue("60s") Duration window, String key) {
    public AuthenticationRateLimitProperties {
        if (limit < 1 || limit > 100_000) {
            throw new IllegalArgumentException("Authentication rate limit must be between 1 and 100000");
        }
        if (window == null || window.compareTo(Duration.ofSeconds(1)) < 0
                || window.compareTo(Duration.ofHours(1)) > 0 || window.getNano() != 0) {
            throw new IllegalArgumentException("Authentication rate window must be whole seconds between 1s and 1h");
        }
        byte[] decoded;
        try {
            decoded = key == null ? new byte[0] : Base64.getDecoder().decode(key);
        } catch (IllegalArgumentException invalidEncoding) {
            throw new IllegalArgumentException("Authentication rate-limit key must be Base64 encoded");
        }
        int length = decoded.length;
        Arrays.fill(decoded, (byte) 0);
        if (length < 32 || length > 128) {
            throw new IllegalArgumentException("Authentication rate-limit key must contain 32 to 128 random bytes");
        }
    }

    @Override
    public String toString() {
        return "AuthenticationRateLimitProperties[limit=" + limit + ", window=" + window + ", key=[REDACTED]]";
    }
}
