package com.enterpriseiam.security.ratelimit;

import com.enterpriseiam.security.web.SecurityProblemSupport;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UrlPathHelper;

/** Runs before bearer authentication and before any credential body is parsed or verified. */
@Component
public final class AuthenticationRateLimitFilter extends OncePerRequestFilter {
    private final AuthenticationRateLimiter limiter;
    private final SecurityProblemSupport problems;

    public AuthenticationRateLimitFilter(AuthenticationRateLimiter limiter, SecurityProblemSupport problems) {
        this.limiter = limiter;
        this.problems = problems;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !applicationPath(request).startsWith("/api/v1/auth/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        // Include validation errors, denied logout attempts and unsupported methods in the no-store policy.
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        String path = applicationPath(request);
        String endpoint = switch (path) {
            case "/api/v1/auth/login" -> "login";
            case "/api/v1/auth/refresh" -> "refresh";
            default -> null;
        };
        if ("POST".equals(request.getMethod()) && endpoint != null) {
            try {
                // Forwarded headers are deliberately ignored: trust configuration belongs at the ingress.
                RateLimitDecision result = limiter.check(request.getRemoteAddr(), endpoint);
                if (!result.allowed()) {
                    response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(result.retryAfterSeconds()));
                    problems.write(request, response, HttpStatus.TOO_MANY_REQUESTS);
                    return;
                }
            } catch (AuthenticationServiceException unavailable) {
                problems.write(request, response, HttpStatus.SERVICE_UNAVAILABLE);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private static String applicationPath(HttpServletRequest request) {
        // Decode consistently with MVC, including percent-encoded letters in an authentication path.
        return UrlPathHelper.defaultInstance.getPathWithinApplication(request);
    }
}
