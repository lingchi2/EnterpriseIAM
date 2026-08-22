package com.enterpriseiam.security.redis;

import com.enterpriseiam.security.config.SecurityProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Service;

/** Redis must use a dedicated noeviction deployment; losing a revocation marker is not acceptable. */
@Service
public final class RedisAccessTokenBlacklist implements AccessTokenBlacklist {
    private static final String PREFIX = "enterpriseiam:access:revoked:";
    private final StringRedisTemplate redis;
    private final Clock clock;
    private final Duration clockSkew;

    public RedisAccessTokenBlacklist(StringRedisTemplate redis, Clock clock, SecurityProperties properties) {
        this.redis = redis;
        this.clock = clock;
        this.clockSkew = properties.clockSkew();
    }

    @Override
    public void revoke(UUID tokenId, Instant expiresAt) {
        Objects.requireNonNull(tokenId, "tokenId");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Duration ttl = Duration.between(clock.instant(), expiresAt.plus(clockSkew));
        if (ttl.isNegative() || ttl.isZero()) {
            return;
        }
        try {
            Boolean result = redis.opsForValue().setIfAbsent(PREFIX + tokenId, "1", ttl);
            if (result == null) {
                throw unavailable(null);
            }
        } catch (DataAccessException exception) {
            throw unavailable(exception);
        }
    }

    @Override
    public boolean isRevoked(UUID tokenId) {
        Objects.requireNonNull(tokenId, "tokenId");
        try {
            Boolean revoked = redis.hasKey(PREFIX + tokenId);
            if (revoked == null) {
                throw unavailable(null);
            }
            return revoked;
        } catch (DataAccessException exception) {
            throw unavailable(exception);
        }
    }

    private static AuthenticationServiceException unavailable(Throwable cause) {
        return new AuthenticationServiceException("Authentication dependency unavailable", cause);
    }
}
