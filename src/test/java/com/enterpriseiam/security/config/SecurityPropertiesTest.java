package com.enterpriseiam.security.config;

import static com.enterpriseiam.security.jwt.JwtTestSupport.PROPERTIES;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SecurityPropertiesTest {
    @ParameterizedTest
    @ValueSource(longs = {-1, 0, 901, 86400})
    void rejectsInvalidAccessTokenLifetime(long seconds) {
        assertThatThrownBy(() -> new SecurityProperties(PROPERTIES.issuer(), PROPERTIES.audience(),
                PROPERTIES.keyId(), PROPERTIES.privateKey(), PROPERTIES.publicKey(),
                Duration.ofSeconds(seconds), PROPERTIES.clockSkew())).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(longs = {-1, 61, 86400})
    void rejectsUnboundedClockSkew(long seconds) {
        assertThatThrownBy(() -> new SecurityProperties(PROPERTIES.issuer(), PROPERTIES.audience(),
                PROPERTIES.keyId(), PROPERTIES.privateKey(), PROPERTIES.publicKey(),
                PROPERTIES.accessTokenTtl(), Duration.ofSeconds(seconds))).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://iam.example.test", "https://user:pass@iam.example.test", "/iam", "https://iam.example.test#bad"})
    void requiresUnambiguousHttpsIssuer(String issuer) {
        assertThatThrownBy(() -> new SecurityProperties(issuer, PROPERTIES.audience(),
                PROPERTIES.keyId(), PROPERTIES.privateKey(), PROPERTIES.publicKey(),
                PROPERTIES.accessTokenTtl(), PROPERTIES.clockSkew())).isInstanceOf(IllegalArgumentException.class);
    }
}
