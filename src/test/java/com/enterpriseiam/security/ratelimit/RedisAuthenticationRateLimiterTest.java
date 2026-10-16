package com.enterpriseiam.security.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.Duration;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationServiceException;

class RedisAuthenticationRateLimiterTest {
    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final RedisAuthenticationRateLimiter limiter = new RedisAuthenticationRateLimiter(redis,
            new AuthenticationRateLimitProperties(20, Duration.ofSeconds(60), KEY));

    @BeforeEach
    void prepare() {
        when(redis.execute(eq(RedisAuthenticationRateLimiter.TAKE), anyList(), anyString(), anyString()))
                .thenReturn(0L);
    }

    @Test
    void admittedRequestExecutesOneAtomicScriptWithBoundedConfiguration() {
        assertThat(limiter.check("192.0.2.10", "login")).isEqualTo(new RateLimitDecision(true, 0));
        verify(redis).execute(eq(RedisAuthenticationRateLimiter.TAKE), anyList(), eq("20"), eq("60000"));
        verifyNoMoreInteractions(redis);
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void distributedKeysAreStableEndpointSeparatedAndContainNoRawAddress() {
        limiter.check("192.0.2.10", "login");
        limiter.check("192.0.2.10", "login");
        limiter.check("192.0.2.10", "refresh");
        limiter.check("192.0.2.11", "login");
        ArgumentCaptor<List<String>> keys = ArgumentCaptor.forClass((Class) List.class);
        verify(redis, times(4)).execute(eq(RedisAuthenticationRateLimiter.TAKE), keys.capture(), eq("20"), eq("60000"));
        List<List<String>> captured = keys.getAllValues();
        assertThat(captured.get(0)).isEqualTo(captured.get(1));
        assertThat(captured.get(0)).isNotEqualTo(captured.get(2)).isNotEqualTo(captured.get(3));
        captured.forEach(key -> {
            assertThat(key).hasSize(1);
            assertThat(key.getFirst()).matches("enterpriseiam:auth:rate:(login|refresh):[a-f0-9]{64}")
                    .doesNotContain("192.0.2");
        });
    }

    @ParameterizedTest
    @ValueSource(longs = {1, 999, 1000, 1001, 59999, 60000})
    void retryAfterRoundsUpWithoutPermittingAnotherAttemptEarly(long milliseconds) {
        when(redis.execute(eq(RedisAuthenticationRateLimiter.TAKE), anyList(), anyString(), anyString()))
                .thenReturn(milliseconds);
        assertThat(limiter.check("192.0.2.10", "refresh"))
                .isEqualTo(new RateLimitDecision(false, (milliseconds + 999) / 1000));
    }

    @Test
    void redisOutageFailsClosed() {
        when(redis.execute(eq(RedisAuthenticationRateLimiter.TAKE), anyList(), anyString(), anyString()))
                .thenThrow(new RedisConnectionFailureException("private internal hostname"));
        assertThatThrownBy(() -> limiter.check("192.0.2.10", "login"))
                .isInstanceOf(AuthenticationServiceException.class)
                .hasMessage("Authentication dependency unavailable");
    }

    @Test
    void nullRedisResultFailsClosed() {
        when(redis.execute(eq(RedisAuthenticationRateLimiter.TAKE), anyList(), anyString(), anyString()))
                .thenReturn(null);
        assertThatThrownBy(() -> limiter.check("192.0.2.10", "login"))
                .isInstanceOf(AuthenticationServiceException.class);
    }

    @ParameterizedTest
    @ValueSource(longs = {-2, -1, 60001, Long.MAX_VALUE})
    void invalidRedisResultFailsClosed(long invalid) {
        when(redis.execute(eq(RedisAuthenticationRateLimiter.TAKE), anyList(), anyString(), anyString()))
                .thenReturn(invalid);
        assertThatThrownBy(() -> limiter.check("192.0.2.10", "login"))
                .isInstanceOf(AuthenticationServiceException.class);
    }

    @Test
    void missingAddressFailsClosedWithoutCreatingUnboundedRedisKeys() {
        assertThatThrownBy(() -> limiter.check(null, "login")).isInstanceOf(AuthenticationServiceException.class);
        assertThatThrownBy(() -> limiter.check(" ", "login")).isInstanceOf(AuthenticationServiceException.class);
        assertThatThrownBy(() -> limiter.check("x".repeat(129), "login"))
                .isInstanceOf(AuthenticationServiceException.class);
        verifyNoInteractions(redis);
    }

    @Test
    void unsupportedEndpointCannotCreateUnboundedKeyNamespaces() {
        assertThatThrownBy(() -> limiter.check("192.0.2.10", "unexpected"))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(redis);
    }
}
