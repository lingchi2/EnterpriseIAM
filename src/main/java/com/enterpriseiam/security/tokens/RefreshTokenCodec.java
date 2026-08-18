package com.enterpriseiam.security.tokens;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;
import org.springframework.security.authentication.BadCredentialsException;

/** Opaque tokens have 256 bits of entropy, so a fast digest is safe for storage. */
final class RefreshTokenCodec {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9_-]{43}");
    private final SecureRandom random = new SecureRandom();

    String generate() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }

    String hash(String rawToken) {
        // Bound attacker-controlled input before allocating or hashing it. The
        // canonical check also rejects alternative encodings of the final bits.
        if (rawToken == null || rawToken.length() != 43
                || !FORMAT.matcher(rawToken).matches()) {
            throw invalidToken();
        }
        byte[] decoded = Base64.getUrlDecoder().decode(rawToken);
        if (decoded.length != 32 || !ENCODER.encodeToString(decoded).equals(rawToken)) {
            throw invalidToken();
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("The required SHA-256 implementation is unavailable", exception);
        }
    }

    static BadCredentialsException invalidToken() {
        return new BadCredentialsException("Invalid authentication credentials");
    }
}
