package com.enterpriseiam.audit.capture;

import com.enterpriseiam.audit.model.AuditEvent;
import com.enterpriseiam.audit.model.AuditPhase;
import com.enterpriseiam.resource.ResourceReference;
import com.enterpriseiam.security.identity.IamPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/** Allowlist-based capture: arbitrary objects and strings are never traversed or stringified. */
record AuditSnapshot(UUID invocationId, String action, String actorId, String method,
        Map<String, String> arguments, String remoteAddress, String userAgent,
        String requestMethod, String requestPath) {
    static final String REDACTED = "[REDACTED]";

    static AuditSnapshot capture(String action, Method method, Object[] arguments) {
        HttpServletRequest request = RequestContextHolder.getRequestAttributes()
                instanceof ServletRequestAttributes attributes ? attributes.getRequest() : null;
        return new AuditSnapshot(UUID.randomUUID(), action, actor(),
                sanitize(method.getDeclaringClass().getName() + "." + method.getName(),
                        AuditEvent.MAX_METHOD_LENGTH),
                arguments(arguments), request == null ? "" : sanitize(request.getRemoteAddr(), 64),
                request == null ? "" : sanitize(request.getHeader("User-Agent"), AuditEvent.MAX_USER_AGENT_LENGTH),
                request == null ? "" : sanitize(request.getMethod(), 16),
                request == null ? "" : path(request.getRequestURI()));
    }

    AuditEvent event(UUID eventId, Instant occurredAt, AuditPhase phase, String outcome) {
        return new AuditEvent(eventId, invocationId, occurredAt, action, phase, actorId,
                method, arguments, remoteAddress, userAgent, requestMethod, requestPath, outcome);
    }

    private static String actor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)
                && authentication.getPrincipal() instanceof IamPrincipal principal) {
            return principal.userId().toString();
        }
        return "anonymous";
    }

    private static Map<String, String> arguments(Object[] arguments) {
        Map<String, String> values = new LinkedHashMap<>();
        int count = Math.min(arguments.length, AuditEvent.MAX_ARGUMENTS);
        for (int index = 0; index < count; index++) {
            values.put("arg" + index, argument(arguments[index]));
        }
        return Map.copyOf(values);
    }

    private static String argument(Object argument) {
        if (argument == null) {
            return "[NULL]";
        }
        if (argument instanceof UUID id) {
            return id.toString();
        }
        if (argument instanceof ResourceReference reference) {
            return reference.id() == null ? "[NULL]" : reference.id().toString();
        }
        if (argument instanceof Enum<?> value) {
            return sanitize(value.name(), AuditEvent.MAX_ARGUMENT_VALUE_LENGTH);
        }
        // Exact JDK types only: no polymorphic Number.toString(), unbounded BigDecimal, or NaN.
        if (argument instanceof Byte || argument instanceof Short
                || argument instanceof Integer || argument instanceof Long) {
            return argument.toString();
        }
        if (argument instanceof Float number && Float.isFinite(number)) {
            return Float.toString(number);
        }
        if (argument instanceof Double number && Double.isFinite(number)) {
            return Double.toString(number);
        }
        return REDACTED;
    }

    private static String path(String requestUri) {
        if (requestUri == null) {
            return "";
        }
        // Servlet requestURI omits queries; defensive stripping also protects nonstandard wrappers.
        int query = requestUri.indexOf('?');
        int fragment = requestUri.indexOf('#');
        int end = requestUri.length();
        if (query >= 0) end = Math.min(end, query);
        if (fragment >= 0) end = Math.min(end, fragment);
        return sanitize(requestUri.substring(0, end), AuditEvent.MAX_REQUEST_PATH_LENGTH);
    }

    static String sanitize(String input, int maximum) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        StringBuilder output = new StringBuilder(Math.min(input.length(), maximum));
        for (int index = 0; index < input.length() && output.length() < maximum;) {
            int codePoint = input.codePointAt(index);
            index += Character.charCount(codePoint);
            if (AuditEvent.unsafeCodePoint(codePoint)) {
                output.append(' ');
            } else if (output.length() + Character.charCount(codePoint) <= maximum) {
                output.appendCodePoint(codePoint);
            } else {
                break;
            }
        }
        return output.toString();
    }
}
