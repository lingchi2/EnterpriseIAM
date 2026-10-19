package com.enterpriseiam.audit.capture;

import static org.assertj.core.api.Assertions.assertThat;

import com.enterpriseiam.audit.model.AuditEvent;
import com.enterpriseiam.audit.model.AuditPhase;
import com.enterpriseiam.resource.ResourceReference;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class AuditSnapshotTest {
    @AfterEach
    void clearContexts() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void capturesOnlyExplicitlyAllowedArgumentTypesAndNeverTraversesOrStringifiesObjects() throws Exception {
        UUID identifier = UUID.randomUUID();
        Object opaque = new Object() {
            @Override public String toString() { throw new AssertionError("Sensitive object stringified"); }
        };
        AuditEvent event = capture(identifier, new ResourceReference(identifier), AuditPhase.STARTED,
                123L, -42, 1.25, Float.NaN, Double.POSITIVE_INFINITY, new BigDecimal("1E+100000"),
                "password-token-plaintext", "secret".toCharArray(), Map.of("password", "secret"),
                List.of("token"), opaque, null);
        assertThat(event.arguments()).containsEntry("arg0", identifier.toString())
                .containsEntry("arg1", identifier.toString()).containsEntry("arg2", "STARTED")
                .containsEntry("arg3", "123").containsEntry("arg4", "-42").containsEntry("arg5", "1.25")
                .containsEntry("arg14", "[NULL]");
        for (int i = 6; i <= 13; i++) assertThat(event.arguments()).containsEntry("arg" + i, "[REDACTED]");
    }

    @Test
    void copiesArgumentValuesAndBoundsNumberOfArguments() throws Exception {
        Object[] input = new Object[1000];
        input[0] = UUID.randomUUID();
        String original = input[0].toString();
        AuditEvent event = capture(input);
        input[0] = UUID.randomUUID();
        assertThat(event.arguments()).hasSize(AuditEvent.MAX_ARGUMENTS).containsEntry("arg0", original);
    }

    @Test
    void sanitizesBoundsMetadataAndIgnoresForwardedHeadersQueriesCookiesAndAuthorization() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/resource?token=secret#fragment");
        request.setQueryString("password=secret");
        request.setRemoteAddr("203.0.113.10");
        request.addHeader("User-Agent", "client\r\n\u202e" + "a".repeat(10000));
        request.addHeader("X-Forwarded-For", "10.0.0.1");
        request.addHeader("Authorization", "Bearer secret-token");
        request.addHeader("Cookie", "session=secret-session");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        AuditEvent event = capture();
        assertThat(event.remoteAddress()).isEqualTo("203.0.113.10");
        assertThat(event.userAgent()).startsWith("client   ").hasSize(AuditEvent.MAX_USER_AGENT_LENGTH);
        assertThat(event.requestPath()).isEqualTo("/api/resource");
        assertThat(event.requestMethod()).isEqualTo("POST");
        assertThat(event.toString()).doesNotContain("secret", "client", "203.0.113.10");
    }

    @Test
    void enormousPathIsBoundedWithoutSplittingSurrogatesAndControlCharactersAreRemoved() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/" + "x".repeat(1022) + "😀\r\n");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        AuditEvent event = capture();
        assertThat(event.requestPath()).hasSize(1023).doesNotContain("\r", "\n", "😀");
        assertThat(AuditSnapshot.sanitize("a\u0000b\u2028c\u2029d\uD800", 100)).isEqualTo("a b c d ");
    }

    @Test
    void anonymousAuthenticationNeverClaimsAnAuthenticatedIdentity() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymous-user",
                List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))));
        assertThat(capture().actorId()).isEqualTo("anonymous");
    }

    private static AuditEvent capture(Object... arguments) throws Exception {
        Method method = AuditSnapshotTest.class.getDeclaredMethod("capture", Object[].class);
        return AuditSnapshot.capture("TEST_CAPTURE", method, arguments)
                .event(UUID.randomUUID(), Instant.parse("2026-10-23T12:00:00Z"), AuditPhase.STARTED, "PENDING");
    }
}
