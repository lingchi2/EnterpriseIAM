package com.enterpriseiam.security.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class AuthenticationRateLimitPropertiesTest {
    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    @Test
    void bindingProvidesBoundedDefaultsAndRedactsSecret() {
        new ApplicationContextRunner().withUserConfiguration(AuthenticationRateLimitConfiguration.class)
                .withPropertyValues("iam.auth.rate-limit.key=" + KEY).run(context -> {
                    assertThat(context).hasNotFailed();
                    AuthenticationRateLimitProperties properties = context.getBean(AuthenticationRateLimitProperties.class);
                    assertThat(properties.limit()).isEqualTo(20);
                    assertThat(properties.window()).isEqualTo(Duration.ofMinutes(1));
                    assertThat(properties.toString()).doesNotContain(KEY);
                });
    }

    @Test
    void absentKeyPreventsStartup() {
        new ApplicationContextRunner().withUserConfiguration(AuthenticationRateLimitConfiguration.class)
                .run(context -> assertThat(context).hasFailed());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"not-base64!", "YWJj"})
    void missingMalformedOrWeakSecretIsRejected(String key) {
        assertThatThrownBy(() -> new AuthenticationRateLimitProperties(20, Duration.ofMinutes(1), key))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 100001})
    void unlimitedOrExcessiveLimitsAreRejected(int limit) {
        assertThatThrownBy(() -> new AuthenticationRateLimitProperties(limit, Duration.ofMinutes(1), KEY))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"PT0S", "PT0.5S", "PT1.5S", "PT3601S", "PT-1S"})
    void invalidWindowsAreRejected(String duration) {
        assertThatThrownBy(() -> new AuthenticationRateLimitProperties(20, Duration.parse(duration), KEY))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
