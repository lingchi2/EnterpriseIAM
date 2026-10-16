package com.enterpriseiam.security.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import com.enterpriseiam.security.web.SecurityProblemSupport;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class AuthenticationRateLimitFilterTest {
    private final AuthenticationRateLimiter limiter = mock(AuthenticationRateLimiter.class);
    private final AuthenticationRateLimitFilter filter = new AuthenticationRateLimitFilter(limiter,
            new SecurityProblemSupport(new ObjectMapper()));
    private final FilterChain chain = mock(FilterChain.class);

    @Test
    void forwardedHeadersCannotChangeDirectClientRateBucket() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setRemoteAddr("192.0.2.10");
        request.addHeader("X-Forwarded-For", "198.51.100.25");
        request.addHeader("Forwarded", "for=198.51.100.26");
        when(limiter.check("192.0.2.10", "login")).thenReturn(new RateLimitDecision(true, 0));
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        verify(limiter).check("192.0.2.10", "login");
        verify(chain).doFilter(request, response);
        assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
    }

    @Test
    void encodedLettersCannotBypassCredentialEndpointLimiter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/%6Cogin");
        when(limiter.check("127.0.0.1", "login")).thenReturn(new RateLimitDecision(false, 1));
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertThat(response.getStatus()).isEqualTo(429);
        verify(limiter).check("127.0.0.1", "login");
        verifyNoInteractions(chain);
    }

    @Test
    void servletContextPrefixDoesNotBypassLimiter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/enterprise/api/v1/auth/refresh");
        request.setContextPath("/enterprise");
        when(limiter.check("127.0.0.1", "refresh")).thenReturn(new RateLimitDecision(false, 2));
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertThat(response.getStatus()).isEqualTo(429);
        verifyNoInteractions(chain);
    }

    @Test
    void authenticatedResourceRequestsAreOutsideCredentialRateLimit() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/resources/123");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        verifyNoInteractions(limiter);
    }

    @Test
    void unsupportedAuthMethodsStillDisableCachingWithoutConsumingCredentialBucket() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        verifyNoInteractions(limiter);
        assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
        assertThat(response.getHeader(HttpHeaders.PRAGMA)).isEqualTo("no-cache");
    }
}
