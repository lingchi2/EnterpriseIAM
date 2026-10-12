package com.enterpriseiam.security.jwt;

import static com.enterpriseiam.security.jwt.JwtTestSupport.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.enterpriseiam.security.config.SecurityProperties;
import org.junit.jupiter.api.Test;

class RsaSigningKeysTest {
    @Test
    void loadsMatchingPkcs8AndX509PemWithoutLeakingKeyMaterial() {
        RsaSigningKeys loaded = RsaSigningKeys.load(PROPERTIES);
        assertThat(loaded.publicKey()).isEqualTo(KEYS.publicKey());
        assertThat(loaded.privateKey()).isEqualTo(KEYS.privateKey());
        assertThat(loaded.toString()).isEqualTo("RsaSigningKeys[REDACTED]");
    }

    @Test
    void rejectsWeakKeys() {
        assertThatThrownBy(() -> RsaSigningKeys.load(properties(keys(2048))))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("3072");
    }

    @Test
    void rejectsMismatchedPair() {
        RsaSigningKeys other = keys(3072);
        SecurityProperties mismatched = new SecurityProperties(PROPERTIES.issuer(), PROPERTIES.audience(),
                PROPERTIES.keyId(), PROPERTIES.privateKey(), pem("PUBLIC KEY", other.publicKey().getEncoded()),
                PROPERTIES.accessTokenTtl(), PROPERTIES.clockSkew());
        assertThatThrownBy(() -> RsaSigningKeys.load(mismatched))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("do not match");
    }
}
