package com.enterpriseiam.security.config;

import com.enterpriseiam.security.jwt.AccessTokenClaimsValidator;
import com.enterpriseiam.security.jwt.RsaSigningKeys;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.time.Clock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SecurityProperties.class)
public class JwtConfiguration {
    @Bean public Clock clock() { return Clock.systemUTC(); }

    @Bean
    public RsaSigningKeys rsaSigningKeys(SecurityProperties properties) {
        return RsaSigningKeys.load(properties);
    }

    @Bean
    public JwtEncoder jwtEncoder(RsaSigningKeys keys, SecurityProperties properties) {
        RSAKey key = new RSAKey.Builder(keys.publicKey()).privateKey(keys.privateKey())
                .keyID(properties.keyId()).build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
    }

    @Bean
    public JwtDecoder jwtDecoder(RsaSigningKeys keys, SecurityProperties properties, Clock clock) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(keys.publicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(new AccessTokenClaimsValidator(properties, clock));
        return decoder;
    }
}
