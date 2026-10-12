package com.enterpriseiam.security.jwt;

import com.enterpriseiam.security.config.JwtConfiguration;
import com.enterpriseiam.security.config.SecurityProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.function.Consumer;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/** Ephemeral test keys never enter production resources. */
public final class JwtTestSupport {
    public static final Instant NOW = Instant.parse("2026-10-23T09:00:00Z");
    public static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    public static final UUID USER_ID = UUID.randomUUID();
    public static final UUID SESSION_ID = UUID.randomUUID();
    public static final UUID TOKEN_ID = UUID.randomUUID();
    public static final RsaSigningKeys KEYS = keys(3072);
    public static final SecurityProperties PROPERTIES = properties(KEYS);
    public static final JwtDecoder DECODER = new JwtConfiguration().jwtDecoder(KEYS, PROPERTIES, CLOCK);

    private JwtTestSupport() { }

    public static SecurityProperties properties(RsaSigningKeys keys) {
        return new SecurityProperties("https://iam.example.test", "enterprise-api", "test-key",
                pem("PRIVATE KEY", keys.privateKey().getEncoded()),
                pem("PUBLIC KEY", keys.publicKey().getEncoded()), Duration.ofMinutes(5), Duration.ofSeconds(30));
    }

    public static RsaSigningKeys keys(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            KeyPair pair = generator.generateKeyPair();
            return new RsaSigningKeys((RSAPrivateKey) pair.getPrivate(), (RSAPublicKey) pair.getPublic());
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    public static ByteArrayResource pem(String label, byte[] data) {
        return new ByteArrayResource(("-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(data)
                + "\n-----END " + label + "-----\n").getBytes(StandardCharsets.US_ASCII));
    }

    public static String signed(Consumer<JWTClaimsSet.Builder> mutation) {
        return signed(mutation, JWSAlgorithm.RS256, "test-key", KEYS);
    }

    public static String signed(Consumer<JWTClaimsSet.Builder> mutation, JWSAlgorithm algorithm,
            String keyId, RsaSigningKeys keys) {
        try {
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(PROPERTIES.issuer()).audience(PROPERTIES.audience())
                    .subject(USER_ID.toString()).jwtID(TOKEN_ID.toString())
                    .issueTime(Date.from(NOW)).notBeforeTime(Date.from(NOW))
                    .expirationTime(Date.from(NOW.plusSeconds(300)))
                    .claim("sid", SESSION_ID.toString()).claim("token_use", "access");
            mutation.accept(claims);
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(algorithm)
                    .type(JOSEObjectType.JWT).keyID(keyId).build(), claims.build());
            jwt.sign(new RSASSASigner(keys.privateKey()));
            return jwt.serialize();
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
