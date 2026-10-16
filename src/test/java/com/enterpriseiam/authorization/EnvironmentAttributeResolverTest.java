package com.enterpriseiam.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class EnvironmentAttributeResolverTest {
    private final EnvironmentAttributeResolver resolver = new EnvironmentAttributeResolver(
            Clock.fixed(Instant.parse("2026-10-23T12:00:00Z"), ZoneOffset.UTC),
            DefaultAbacPolicyTest.properties(List.of("10.0.0.0/8")));

    @AfterEach
    void cleanUp() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void usesSocketPeerAndIgnoresSpoofedForwardingHeaders() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.4");
        request.addHeader("X-Forwarded-For", "10.1.2.3");
        request.addHeader("Forwarded", "for=10.1.2.3");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        assertThat(resolver.resolve()).hasValueSatisfying(environment -> {
            assertThat(environment.remoteAddress()).isEqualTo("203.0.113.4");
            assertThat(environment.time().toInstant()).isEqualTo(Instant.parse("2026-10-23T12:00:00Z"));
        });
    }

    @Test
    void rejectsMissingContextAndHostnames() {
        assertThat(resolver.resolve()).isEmpty();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("trusted.example.com");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        assertThat(resolver.resolve()).isEmpty();
    }
}
