package com.enterpriseiam.security.jwt;

import com.enterpriseiam.security.config.SecurityProperties;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.core.io.Resource;

/** Deliberately never generates keys: every replica must use the same managed signing key. */
public record RsaSigningKeys(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
    private static final int MAX_KEY_FILE_BYTES = 16_384;

    public static RsaSigningKeys load(SecurityProperties properties) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(
                    decodePem(properties.privateKey(), "PRIVATE KEY")));
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(
                    decodePem(properties.publicKey(), "PUBLIC KEY")));
            if (privateKey.getModulus().bitLength() < 3072 || publicKey.getModulus().bitLength() < 3072
                    || publicKey.getPublicExponent().compareTo(BigInteger.valueOf(65_537)) < 0
                    || !publicKey.getPublicExponent().testBit(0)) {
                throw new IllegalArgumentException("RSA signing keys must be at least 3072 bits with exponent >= 65537");
            }
            if (!privateKey.getModulus().equals(publicKey.getModulus())) {
                throw new IllegalArgumentException("Configured RSA private and public keys do not match");
            }
            byte[] challenge = "EnterpriseIAM startup key-pair verification".getBytes(StandardCharsets.US_ASCII);
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(challenge);
            byte[] signed = signer.sign();
            signer.initVerify(publicKey);
            signer.update(challenge);
            if (!signer.verify(signed)) {
                throw new IllegalArgumentException("Configured RSA private and public keys do not match");
            }
            return new RsaSigningKeys(privateKey, publicKey);
        } catch (GeneralSecurityException | IOException | ClassCastException exception) {
            throw new IllegalStateException("Unable to load configured RSA PKCS8 private and X509 public keys", exception);
        }
    }

    private static byte[] decodePem(Resource resource, String label) throws IOException {
        byte[] content;
        try (InputStream stream = resource.getInputStream()) {
            content = stream.readNBytes(MAX_KEY_FILE_BYTES + 1);
        }
        if (content.length > MAX_KEY_FILE_BYTES) {
            throw new IllegalArgumentException("RSA key file exceeds maximum size");
        }
        String pem = new String(content, StandardCharsets.US_ASCII).strip();
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        if (!pem.startsWith(begin) || !pem.endsWith(end)) {
            throw new IllegalArgumentException("Expected PEM " + label);
        }
        String encoded = pem.substring(begin.length(), pem.length() - end.length()).replaceAll("\\s", "");
        return Base64.getDecoder().decode(encoded);
    }

    @Override
    public String toString() {
        return "RsaSigningKeys[REDACTED]";
    }
}
