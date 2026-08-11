package com.enterpriseiam.security.jwt;

import com.enterpriseiam.security.config.SecurityProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/** All claims are mandatory; a cryptographically valid but incomplete token is never authenticated. */
public final class AccessTokenClaimsValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID = new OAuth2Error("invalid_token", "Invalid access token", null);
    private final SecurityProperties properties;
    private final Clock clock;

    public AccessTokenClaimsValidator(SecurityProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        try {
            Instant issuedAt = token.getIssuedAt();
            Instant notBefore = token.getNotBefore();
            Instant expiresAt = token.getExpiresAt();
            Instant now = clock.instant();
            Duration skew = properties.clockSkew();
            boolean valid = "RS256".equals(token.getHeaders().get("alg"))
                    && "JWT".equals(token.getHeaders().get("typ"))
                    && properties.keyId().equals(token.getHeaders().get("kid"))
                    && properties.issuer().equals(token.getClaimAsString("iss"))
                    && token.getAudience() != null && token.getAudience().contains(properties.audience())
                    && "access".equals(token.getClaims().get("token_use"))
                    && isUuid(token.getClaims().get("sub"))
                    && isUuid(token.getClaims().get("sid"))
                    && isUuid(token.getClaims().get("jti"))
                    && issuedAt != null && notBefore != null && expiresAt != null
                    && !issuedAt.isAfter(now.plus(skew))
                    && !notBefore.isAfter(now.plus(skew))
                    && !notBefore.isBefore(issuedAt)
                    && notBefore.isBefore(expiresAt)
                    && issuedAt.isBefore(expiresAt)
                    && Duration.between(issuedAt, expiresAt).compareTo(properties.accessTokenTtl()) <= 0
                    && expiresAt.plus(skew).isAfter(now);
            return valid ? OAuth2TokenValidatorResult.success() : OAuth2TokenValidatorResult.failure(INVALID);
        } catch (RuntimeException invalidClaims) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
    }

    private static boolean isUuid(Object claim) {
        if (!(claim instanceof String value)) {
            return false;
        }
        try {
            return UUID.fromString(value).toString().equals(value);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}
