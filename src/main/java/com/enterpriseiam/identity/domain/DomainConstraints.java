package com.enterpriseiam.identity.domain;

import java.util.Locale;
import java.util.regex.Pattern;

/** Domain invariants also backed by migration-level constraints wherever practical. */
final class DomainConstraints {

    private static final Pattern ROLE_NAME = Pattern.compile("[A-Z][A-Z0-9_]*");
    private static final Pattern PERMISSION_NAME =
            Pattern.compile("[A-Z][A-Z0-9_]*(?::[A-Z][A-Z0-9_]*)*");
    private static final Pattern ENCODED_PASSWORD =
            Pattern.compile("\\{[A-Za-z0-9@._-]+\\}\\S+");

    private DomainConstraints() {}

    static String email(String value) {
        String email = text(value, "email", 254).toLowerCase(Locale.ROOT);
        int separator = email.indexOf('@');
        if (email.length() > 254 || separator < 1 || separator != email.lastIndexOf('@')
                || separator == email.length() - 1
                || email.codePoints().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("email must have a local part and a domain");
        }
        return email;
    }

    static String passwordHash(String value) {
        if (value == null || value.length() > 255 || !ENCODED_PASSWORD.matcher(value).matches()
                || value.startsWith("{noop}")) {
            throw new IllegalArgumentException("passwordHash must be an encoded, prefixed password");
        }
        return value;
    }

    static String department(String value) {
        return text(value, "department", 100);
    }

    static short clearanceLevel(short value) {
        if (value < 0 || value > 4) {
            throw new IllegalArgumentException("clearanceLevel must be between 0 and 4");
        }
        return value;
    }

    static String roleName(String value) {
        return authorizationName(value, "role name", 64, ROLE_NAME);
    }

    static String permissionName(String value) {
        return authorizationName(value, "permission name", 128, PERMISSION_NAME);
    }

    private static String authorizationName(String value, String field, int maxLength,
            Pattern pattern) {
        String normalized = text(value, field, maxLength).toUpperCase(Locale.ROOT);
        if (normalized.length() > maxLength || !pattern.matcher(normalized).matches()) {
            throw new IllegalArgumentException(field + " has an invalid authorization identifier");
        }
        return normalized;
    }

    private static String text(String value, String field, int maxLength) {
        if (value == null) {
            throw new IllegalArgumentException(field + " is required");
        }
        String normalized = value.trim();
        if (normalized.isEmpty() || normalized.length() > maxLength
                || normalized.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " must contain between 1 and " + maxLength
                    + " characters and no control characters");
        }
        return normalized;
    }
}
