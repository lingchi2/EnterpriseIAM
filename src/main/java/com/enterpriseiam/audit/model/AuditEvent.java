package com.enterpriseiam.audit.model;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * An immutable snapshot captured on the calling thread. It contains no live request, principal,
 * exception, arguments, or result objects that an asynchronous serializer could inspect later.
 */
public record AuditEvent(UUID id, UUID invocationId, Instant occurredAt, String action,
        AuditPhase phase, String actorId, String method, Map<String, String> arguments,
        String remoteAddress, String userAgent, String requestMethod, String requestPath,
        String outcomeType) {
    public static final int MAX_ARGUMENTS = 32;
    public static final int MAX_ARGUMENT_VALUE_LENGTH = 128;
    public static final int MAX_METHOD_LENGTH = 256;
    public static final int MAX_USER_AGENT_LENGTH = 256;
    public static final int MAX_REQUEST_PATH_LENGTH = 1024;

    public AuditEvent {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(invocationId, "invocationId");
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(phase, "phase");
        identifier(action, "action");
        identifier(outcomeType, "outcomeType");
        text(actorId, 36, "actorId");
        if (!"anonymous".equals(actorId)) {
            if (!UUID.fromString(actorId).toString().equals(actorId)) {
                throw new IllegalArgumentException("Invalid audit actor identity");
            }
        }
        text(method, MAX_METHOD_LENGTH, "method");
        arguments = Map.copyOf(Objects.requireNonNull(arguments, "arguments"));
        if (arguments.size() > MAX_ARGUMENTS) {
            throw new IllegalArgumentException("Too many audit arguments");
        }
        arguments.forEach((key, value) -> {
            text(key, 64, "argument key");
            text(value, MAX_ARGUMENT_VALUE_LENGTH, "argument value");
        });
        text(remoteAddress, 64, "remoteAddress");
        text(userAgent, MAX_USER_AGENT_LENGTH, "userAgent");
        text(requestMethod, 16, "requestMethod");
        text(requestPath, MAX_REQUEST_PATH_LENGTH, "requestPath");
    }

    private static void identifier(String value, String field) {
        Objects.requireNonNull(value, field);
        if (!value.matches("[A-Z][A-Z0-9_]{0,63}")) {
            throw new IllegalArgumentException("Invalid audit " + field);
        }
    }

    private static void text(String value, int maximum, String field) {
        Objects.requireNonNull(value, field);
        if (value.length() > maximum || value.codePoints().anyMatch(AuditEvent::unsafeCodePoint)) {
            throw new IllegalArgumentException("Invalid audit " + field);
        }
    }

    public static boolean unsafeCodePoint(int codePoint) {
        int type = Character.getType(codePoint);
        return Character.isISOControl(codePoint) || type == Character.FORMAT
                || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR
                || type == Character.SURROGATE;
    }

    @Override
    public String toString() {
        return "AuditEvent[id=" + id + ", invocationId=" + invocationId + ", phase=" + phase + "]";
    }
}
