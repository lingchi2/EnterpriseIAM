package com.enterpriseiam.security.redis;

import static com.enterpriseiam.security.jwt.JwtTestSupport.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.AuthenticationServiceException;

class RedisAccessTokenBlacklistTest {
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> values = mock(ValueOperations.class);
    private final RedisAccessTokenBlacklist blacklist = new RedisAccessTokenBlacklist(redis, CLOCK, PROPERTIES);
    private final String key = "enterpriseiam:access:revoked:" + TOKEN_ID;

    @BeforeEach
    void configureValues() { when(redis.opsForValue()).thenReturn(values); }

    @Test
    void storesOnlyJtiWithTtlCoveringClockSkew() {
        when(values.setIfAbsent(key, "1", Duration.ofSeconds(330))).thenReturn(true);
        blacklist.revoke(TOKEN_ID, NOW.plusSeconds(300));
        verify(values).setIfAbsent(key, "1", Duration.ofSeconds(330));
    }

    @Test
    void revocationDuringExpirationGracePeriodIsStillStored() {
        when(values.setIfAbsent(key, "1", Duration.ofSeconds(10))).thenReturn(true);
        blacklist.revoke(TOKEN_ID, NOW.minusSeconds(20));
        verify(values).setIfAbsent(key, "1", Duration.ofSeconds(10));
    }

    @Test
    void alreadyUnacceptableTokenNeedsNoRedisWrite() {
        blacklist.revoke(TOKEN_ID, NOW.minusSeconds(30));
        verifyNoInteractions(values);
    }

    @Test
    void reportsExistingAndMissingMarkers() {
        when(redis.hasKey(key)).thenReturn(true, false);
        assertThat(blacklist.isRevoked(TOKEN_ID)).isTrue();
        assertThat(blacklist.isRevoked(TOKEN_ID)).isFalse();
    }

    @Test
    void rejectsRequestsAndLogoutWhenRedisFails() {
        when(redis.hasKey(key)).thenThrow(new RedisConnectionFailureException("Connection failed"));
        when(values.setIfAbsent(key, "1", Duration.ofSeconds(330)))
                .thenThrow(new RedisConnectionFailureException("Connection failed"));
        assertThatThrownBy(() -> blacklist.isRevoked(TOKEN_ID)).isInstanceOf(AuthenticationServiceException.class);
        assertThatThrownBy(() -> blacklist.revoke(TOKEN_ID, NOW.plusSeconds(300)))
                .isInstanceOf(AuthenticationServiceException.class);
    }

    @Test
    void ambiguousRedisResultFailsClosed() {
        when(redis.hasKey(key)).thenReturn(null);
        when(values.setIfAbsent(key, "1", Duration.ofSeconds(330))).thenReturn(null);
        assertThatThrownBy(() -> blacklist.isRevoked(TOKEN_ID)).isInstanceOf(AuthenticationServiceException.class);
        assertThatThrownBy(() -> blacklist.revoke(TOKEN_ID, NOW.plusSeconds(300)))
                .isInstanceOf(AuthenticationServiceException.class);
    }
}
