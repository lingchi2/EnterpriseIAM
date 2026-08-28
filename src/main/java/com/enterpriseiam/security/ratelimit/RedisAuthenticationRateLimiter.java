package com.enterpriseiam.security.ratelimit;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;

/**
 * One atomic Redis script implements a shared fixed window without extending it on rejected attempts.
 * HMAC keys avoid retaining raw client addresses in Redis. Every replica must share the same secret.
 */
@Component
public final class RedisAuthenticationRateLimiter implements AuthenticationRateLimiter {
    static final DefaultRedisScript<Long> TAKE = new DefaultRedisScript<>("""
            local current = redis.call('GET', KEYS[1])
            if current and tonumber(current) >= tonumber(ARGV[1]) then
                local ttl = redis.call('PTTL', KEYS[1])
                if ttl < 0 then
                    redis.call('PEXPIRE', KEYS[1], ARGV[2])
                    ttl = tonumber(ARGV[2])
                end
                return math.max(1, ttl)
            end
            local count = redis.call('INCR', KEYS[1])
            if count == 1 or redis.call('PTTL', KEYS[1]) < 0 then
                redis.call('PEXPIRE', KEYS[1], ARGV[2])
            end
            return 0
            """, Long.class);
    private static final String PREFIX = "enterpriseiam:auth:rate:";
    private final StringRedisTemplate redis;
    private final AuthenticationRateLimitProperties properties;
    private final SecretKeySpec hmacKey;

    public RedisAuthenticationRateLimiter(StringRedisTemplate redis, AuthenticationRateLimitProperties properties) {
        this.redis = redis;
        this.properties = properties;
        byte[] decoded = Base64.getDecoder().decode(properties.key());
        this.hmacKey = new SecretKeySpec(decoded, "HmacSHA256");
        Arrays.fill(decoded, (byte) 0);
    }

    @Override
    public RateLimitDecision check(String remoteAddress, String endpoint) {
        if (!"login".equals(endpoint) && !"refresh".equals(endpoint)) {
            throw new IllegalArgumentException("Unsupported authentication endpoint");
        }
        if (remoteAddress == null || remoteAddress.isBlank() || remoteAddress.length() > 128) {
            throw unavailable(null);
        }
        try {
            String key = PREFIX + endpoint + ":" + addressDigest(remoteAddress);
            Long waitMillis = redis.execute(TAKE, List.of(key), Integer.toString(properties.limit()),
                    Long.toString(properties.window().toMillis()));
            if (waitMillis == null || waitMillis < 0 || waitMillis > properties.window().toMillis()) {
                throw unavailable(null);
            }
            return waitMillis == 0 ? new RateLimitDecision(true, 0)
                    : new RateLimitDecision(false, Math.max(1, (waitMillis + 999) / 1_000));
        } catch (DataAccessException exception) {
            throw unavailable(exception);
        }
    }

    private String addressDigest(String address) {
        try {
            // Mac is not thread safe; independent instances avoid contention and state sharing.
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(hmacKey);
            return HexFormat.of().formatHex(mac.doFinal(address.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException failure) {
            throw unavailable(failure);
        }
    }

    private static AuthenticationServiceException unavailable(Throwable cause) {
        return new AuthenticationServiceException("Authentication dependency unavailable", cause);
    }
}
