package com.enterpriseiam.security.jwt;

import com.enterpriseiam.security.config.SecurityProperties;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.stereotype.Service;

@Service
public class AccessTokenService {
    private final JwtEncoder encoder;
    private final SecurityProperties properties;
    private final Clock clock;

    public AccessTokenService(JwtEncoder encoder, SecurityProperties properties, Clock clock) {
        this.encoder = encoder;
        this.properties = properties;
        this.clock = clock;
    }

    /** Call only after creating/verifying the subject's durable authentication session. */
    public IssuedAccessToken issue(UUID userId, UUID sessionId) {
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(sessionId, "sessionId");
        UUID tokenId = UUID.randomUUID();
        Instant issuedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plus(properties.accessTokenTtl());
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer()).audience(List.of(properties.audience()))
                .subject(userId.toString()).id(tokenId.toString())
                .issuedAt(issuedAt).notBefore(issuedAt).expiresAt(expiresAt)
                .claim("sid", sessionId.toString()).claim("token_use", "access").build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(properties.keyId()).type("JWT").build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new IssuedAccessToken(token, tokenId, expiresAt);
    }
}
