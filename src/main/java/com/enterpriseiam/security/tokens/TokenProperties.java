package com.enterpriseiam.security.tokens;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.tokens")
public record TokenProperties(Duration refreshTokenTtl) {

    public TokenProperties {
        if (refreshTokenTtl == null) {
            refreshTokenTtl = Duration.ofDays(30);
        }
        if (refreshTokenTtl.compareTo(Duration.ofMinutes(1)) < 0
                || refreshTokenTtl.compareTo(Duration.ofDays(90)) > 0) {
            throw new IllegalArgumentException("Refresh token TTL must be between 1 minute and 90 days");
        }
    }
}
