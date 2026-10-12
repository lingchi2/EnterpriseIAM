package com.enterpriseiam.security.jwt;

import static com.enterpriseiam.security.jwt.JwtTestSupport.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.enterpriseiam.security.config.JwtConfiguration;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Date;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

class AccessTokenServiceTest {
    @Test
    void issuesMinimalSignedAccessTokenWithUniqueIdsAndBoundedExpiry() {
        AccessTokenService service = new AccessTokenService(
                new JwtConfiguration().jwtEncoder(KEYS, PROPERTIES), PROPERTIES, CLOCK);
        IssuedAccessToken first = service.issue(USER_ID, SESSION_ID);
        IssuedAccessToken second = service.issue(USER_ID, SESSION_ID);
        Jwt decoded = DECODER.decode(first.token());

        assertThat(decoded.getSubject()).isEqualTo(USER_ID.toString());
        assertThat(decoded.getClaimAsString("sid")).isEqualTo(SESSION_ID.toString());
        assertThat(decoded.getId()).isEqualTo(first.tokenId().toString());
        assertThat(first.tokenId()).isNotEqualTo(second.tokenId());
        assertThat(first.expiresAt()).isEqualTo(NOW.plusSeconds(300));
        assertThat(decoded.getClaims()).containsOnlyKeys("iss", "aud", "sub", "jti", "iat", "nbf", "exp", "sid", "token_use");
        assertThat(first.toString()).doesNotContain(first.token());
    }

    @ParameterizedTest
    @ValueSource(strings = {"iss", "aud", "sub", "jti", "iat", "nbf", "exp", "sid", "token_use"})
    void rejectsEveryMissingMandatoryClaim(String claim) {
        assertThatThrownBy(() -> DECODER.decode(signed(builder -> builder.claim(claim, null))))
                .isInstanceOf(JwtException.class);
    }

    @ParameterizedTest
    @MethodSource("invalidClaims")
    void rejectsInvalidClaimValues(Consumer<JWTClaimsSet.Builder> invalid) {
        assertThatThrownBy(() -> DECODER.decode(signed(invalid))).isInstanceOf(JwtException.class);
    }

    static Stream<Consumer<JWTClaimsSet.Builder>> invalidClaims() {
        return Stream.of(
                builder -> builder.issuer("https://attacker.example.test"),
                builder -> builder.audience("another-api"),
                builder -> builder.subject("not-a-user-id"),
                builder -> builder.jwtID("1-1-1-1-1"),
                builder -> builder.claim("sid", 123),
                builder -> builder.claim("sid", "invalid-session"),
                builder -> builder.claim("token_use", "refresh"),
                builder -> builder.expirationTime(Date.from(NOW.minusSeconds(31))),
                builder -> builder.expirationTime(Date.from(NOW.minusSeconds(30))),
                builder -> builder.issueTime(Date.from(NOW.plusSeconds(31))),
                builder -> builder.notBeforeTime(Date.from(NOW.plusSeconds(31))),
                builder -> builder.notBeforeTime(Date.from(NOW.minusSeconds(1))),
                builder -> builder.expirationTime(Date.from(NOW.plusSeconds(301))),
                builder -> builder.claim("exp", "tomorrow"));
    }

    @Test
    void rejectsNonRs256AlgorithmsAndUnexpectedKeyId() {
        assertThatThrownBy(() -> DECODER.decode(signed(builder -> {}, JWSAlgorithm.RS512, "test-key", KEYS)))
                .isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> DECODER.decode(signed(builder -> {}, JWSAlgorithm.RS256, "other-key", KEYS)))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsIncorrectSignatureAndUnsignedToken() {
        assertThatThrownBy(() -> DECODER.decode(signed(builder -> {}, JWSAlgorithm.RS256, "test-key", keys(3072))))
                .isInstanceOf(JwtException.class);
        String valid = signed(builder -> {});
        String[] parts = valid.split("\\.");
        assertThatThrownBy(() -> DECODER.decode(parts[0] + "." + parts[1] + "."))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsHmacAlgorithmConfusionAndPlainJwt() throws Exception {
        JWTClaimsSet claims = SignedJWT.parse(signed(builder -> {})).getJWTClaimsSet();
        SignedJWT hmac = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("test-key").build(), claims);
        hmac.sign(new MACSigner(new byte[32]));
        assertThatThrownBy(() -> DECODER.decode(hmac.serialize())).isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> DECODER.decode(new PlainJWT(claims).serialize())).isInstanceOf(JwtException.class);
    }

    @Test
    void appliesClockSkewOnlyUntilExactExpiryBoundary() {
        String grace = signed(builder -> builder.issueTime(Date.from(NOW.minusSeconds(300)))
                .notBeforeTime(Date.from(NOW.minusSeconds(300))).expirationTime(Date.from(NOW.minusSeconds(29))));
        assertThat(DECODER.decode(grace).getId()).isEqualTo(TOKEN_ID.toString());
        String expired = signed(builder -> builder.issueTime(Date.from(NOW.minusSeconds(300)))
                .notBeforeTime(Date.from(NOW.minusSeconds(300))).expirationTime(Date.from(NOW.minusSeconds(30))));
        assertThatThrownBy(() -> DECODER.decode(expired)).isInstanceOf(JwtException.class);
    }
}
