package com.enterpriseiam.security.config;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;

/** Startup validation prevents insecure fallback keys, token lifetimes, and identifiers. */
@ConfigurationProperties("iam.security")
public record SecurityProperties(String issuer, String audience, String keyId,
        Resource privateKey, Resource publicKey,
        @DefaultValue("5m") Duration accessTokenTtl,
        @DefaultValue("30s") Duration clockSkew) {

    public SecurityProperties {
        requireText(issuer, "issuer");
        URI issuerUri = URI.create(issuer);
        if (!"https".equals(issuerUri.getScheme()) || issuerUri.getHost() == null
                || issuerUri.getUserInfo() != null || issuerUri.getFragment() != null
                || issuerUri.getQuery() != null) {
            throw new IllegalArgumentException("iam.security.issuer must be an HTTPS issuer URL");
        }
        requireText(audience, "audience");
        requireText(keyId, "key-id");
        if (!keyId.matches("[A-Za-z0-9._-]{1,100}")) {
            throw new IllegalArgumentException("iam.security.key-id is invalid");
        }
        Objects.requireNonNull(privateKey, "iam.security.private-key is required");
        Objects.requireNonNull(publicKey, "iam.security.public-key is required");
        Objects.requireNonNull(accessTokenTtl, "access-token-ttl is required");
        Objects.requireNonNull(clockSkew, "clock-skew is required");
        if (accessTokenTtl.compareTo(Duration.ofSeconds(1)) < 0
                || accessTokenTtl.compareTo(Duration.ofMinutes(15)) > 0
                || accessTokenTtl.getNano() != 0) {
            throw new IllegalArgumentException("Access token TTL must be whole seconds between 1s and 15m");
        }
        if (clockSkew.isNegative() || clockSkew.compareTo(Duration.ofMinutes(1)) > 0
                || clockSkew.getNano() != 0) {
            throw new IllegalArgumentException("Clock skew must be whole seconds between 0s and 60s");
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank() || !value.equals(value.strip()) || value.length() > 500) {
            throw new IllegalArgumentException("iam.security." + name + " is required and must be valid");
        }
    }
}
