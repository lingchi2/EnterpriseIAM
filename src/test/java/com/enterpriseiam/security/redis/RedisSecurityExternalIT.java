package com.enterpriseiam.security.redis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

import com.enterpriseiam.security.jwt.JwtTestSupport;
import com.enterpriseiam.security.ratelimit.AuthenticationRateLimitProperties;
import com.enterpriseiam.security.ratelimit.RedisAuthenticationRateLimiter;
import io.lettuce.core.resource.DefaultClientResources;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationServiceException;

/** Explicit external-services profile: requires a disposable, password-protected Redis instance. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RedisSecurityExternalIT {
    private DefaultClientResources resources;
    private LettuceConnectionFactory connections;
    private StringRedisTemplate redis;

    @BeforeAll
    void connect() {
        var server = new RedisStandaloneConfiguration(environment("IAM_TEST_REDIS_HOST"),
                Integer.parseInt(environment("IAM_TEST_REDIS_PORT")));
        server.setPassword(RedisPassword.of(environment("IAM_TEST_REDIS_PASSWORD")));
        resources = DefaultClientResources.builder().ioThreadPoolSize(2).computationThreadPoolSize(2).build();
        connections = new LettuceConnectionFactory(server, LettuceClientConfiguration.builder()
                .clientResources(resources).commandTimeout(Duration.ofSeconds(2)).build());
        connections.afterPropertiesSet();
        connections.start();
        redis = new StringRedisTemplate(connections);
        assertThat(redis.execute((org.springframework.data.redis.core.RedisCallback<String>) c -> c.ping()))
                .isEqualTo("PONG");
    }

    @AfterAll
    void close() {
        if (connections != null) connections.destroy();
        if (resources != null) resources.shutdown();
    }

    @Test
    void luaAtomicallyLimitsConcurrentRequestsAndSeparatesEndpoints() throws Exception {
        var limiter = limiter(20, Duration.ofSeconds(60));
        String address = "test-" + UUID.randomUUID();
        try (var workers = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Boolean>> outcomes = new ArrayList<>();
            for (int i = 0; i < 40; i++) {
                outcomes.add(workers.submit(() -> limiter.check(address, "login").allowed()));
            }
            int admitted = 0;
            for (var result : outcomes) if (result.get()) admitted++;
            assertThat(admitted).isEqualTo(20);
        }
        assertThat(limiter.check(address, "login").retryAfterSeconds()).isBetween(1L, 60L);
        assertThat(limiter.check(address, "refresh").allowed()).isTrue();
    }

    @Test
    void rateWindowExpiresWithoutARefreshFromRejectedRequests() {
        var limiter = limiter(1, Duration.ofSeconds(1));
        String address = "test-" + UUID.randomUUID();
        assertThat(limiter.check(address, "login").allowed()).isTrue();
        assertThat(limiter.check(address, "login").allowed()).isFalse();
        await().atMost(Duration.ofSeconds(4)).pollInterval(Duration.ofMillis(50))
                .until(() -> limiter.check(address, "login").allowed());
    }

    @Test
    void revocationIsIdempotentAndExpiresAtTokenDeadlinePlusTolerance() {
        Clock clock = Clock.systemUTC();
        var blacklist = new RedisAccessTokenBlacklist(redis, clock, JwtTestSupport.PROPERTIES);
        UUID tokenId = UUID.randomUUID();
        String key = "enterpriseiam:access:revoked:" + tokenId;
        try {
            assertThat(blacklist.isRevoked(tokenId)).isFalse();
            Instant expires = clock.instant().plusSeconds(5);
            blacklist.revoke(tokenId, expires);
            assertThat(blacklist.isRevoked(tokenId)).isTrue();
            long ttl = redis.getExpire(key, java.util.concurrent.TimeUnit.MILLISECONDS);
            long expected = Duration.ofSeconds(5).plus(JwtTestSupport.PROPERTIES.clockSkew()).toMillis();
            assertThat(ttl).isBetween(expected - 2_000, expected);
            blacklist.revoke(tokenId, expires.plusSeconds(60));
            assertThat(redis.getExpire(key, java.util.concurrent.TimeUnit.MILLISECONDS)).isLessThanOrEqualTo(ttl);
            UUID expired = UUID.randomUUID();
            blacklist.revoke(expired, clock.instant().minus(JwtTestSupport.PROPERTIES.clockSkew()).minusSeconds(1));
            assertThat(blacklist.isRevoked(expired)).isFalse();
        } finally {
            redis.delete(key);
        }
    }

    @Test
    void realRedisAuthenticationFailureFailsClosed() {
        // A distinct invalid credential exercises Lettuce's actual authentication error translation.
        var server = new RedisStandaloneConfiguration(environment("IAM_TEST_REDIS_HOST"),
                Integer.parseInt(environment("IAM_TEST_REDIS_PORT")));
        server.setPassword(RedisPassword.of("invalid-" + UUID.randomUUID()));
        var denied = new LettuceConnectionFactory(server, LettuceClientConfiguration.builder()
                .clientResources(resources).commandTimeout(Duration.ofSeconds(1)).build());
        denied.afterPropertiesSet();
        denied.start();
        try {
            var blacklist = new RedisAccessTokenBlacklist(new StringRedisTemplate(denied),
                    Clock.systemUTC(), JwtTestSupport.PROPERTIES);
            assertThatThrownBy(() -> blacklist.isRevoked(UUID.randomUUID()))
                    .isInstanceOf(AuthenticationServiceException.class);
        } finally {
            denied.destroy();
        }
    }

    private RedisAuthenticationRateLimiter limiter(int maximum, Duration window) {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        return new RedisAuthenticationRateLimiter(redis,
                new AuthenticationRateLimitProperties(maximum, window, Base64.getEncoder().encodeToString(key)));
    }

    private static String environment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException(name + " must target disposable Redis");
        return value;
    }
}
