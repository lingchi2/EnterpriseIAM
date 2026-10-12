package com.enterpriseiam.security.tokens;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.BadCredentialsException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RefreshTokenCodecTest {

    private final RefreshTokenCodec codec = new RefreshTokenCodec();

    @Test
    void generatesCanonical256BitTokensAndStoresOnlyTheirSha256Digest() throws Exception {
        String rawToken = codec.generate();
        assertEquals(43, rawToken.length());
        assertEquals(32, Base64.getUrlDecoder().decode(rawToken).length);
        assertTrue(rawToken.matches("[A-Za-z0-9_-]{43}"));
        assertNotEquals(rawToken, codec.generate());
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(rawToken.getBytes(StandardCharsets.US_ASCII))), codec.hash(rawToken));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA A"})
    void rejectsInvalidLengthPaddingAlphabetAndNoncanonicalFinalBits(String rawToken) {
        assertThrows(BadCredentialsException.class, () -> codec.hash(rawToken));
    }

    @Test
    void rejectsUnboundedInputAndDoesNotIncludeSecretsInExceptionsOrRecords() {
        String rawToken = "private".repeat(100_000);
        var exception = assertThrows(BadCredentialsException.class, () -> codec.hash(rawToken));
        assertFalse(exception.getMessage().contains("private"));
        String valid = codec.generate();
        var issued = new IssuedRefreshToken(valid, UUID.randomUUID(), UUID.randomUUID(), Instant.now());
        assertFalse(issued.toString().contains(valid));
        assertTrue(issued.toString().contains("[REDACTED]"));
    }

    @Test
    void refreshLifetimeHasConservativeDefaultsAndExplicitBounds() {
        assertEquals(Duration.ofDays(30), new TokenProperties(null).refreshTokenTtl());
        assertEquals(Duration.ofDays(90), new TokenProperties(Duration.ofDays(90)).refreshTokenTtl());
        assertThrows(IllegalArgumentException.class, () -> new TokenProperties(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new TokenProperties(Duration.ofSeconds(59)));
        assertThrows(IllegalArgumentException.class, () -> new TokenProperties(Duration.ofDays(91)));
    }
}
