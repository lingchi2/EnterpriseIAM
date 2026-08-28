package com.enterpriseiam.security.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

/** One representation for security failures in both servlet filters and MVC method invocation. */
@Component
public final class SecurityProblemSupport implements AuthenticationEntryPoint, AccessDeniedHandler {
    private final ObjectMapper mapper;

    public SecurityProblemSupport(ObjectMapper mapper) { this.mapper = mapper; }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException {
        write(request, response, status(exception));
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException exception) throws IOException {
        write(request, response, HttpStatus.FORBIDDEN);
    }

    public ResponseEntity<ProblemDetail> response(HttpServletRequest request, HttpStatus status) {
        return ResponseEntity.status(status).headers(headers(status)).body(problem(request, status));
    }

    public HttpStatus status(AuthenticationException exception) {
        return exception instanceof AuthenticationServiceException
                ? HttpStatus.SERVICE_UNAVAILABLE : HttpStatus.UNAUTHORIZED;
    }

    public void write(HttpServletRequest request, HttpServletResponse response, HttpStatus status)
            throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(status.value());
        headers(status).forEach((key, values) -> values.forEach(value -> response.addHeader(key, value)));
        mapper.writeValue(response.getOutputStream(), problem(request, status));
    }

    private static HttpHeaders headers(HttpStatus status) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        headers.setCacheControl("no-store");
        headers.setPragma("no-cache");
        if (status == HttpStatus.UNAUTHORIZED) {
            headers.set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        }
        if (status == HttpStatus.SERVICE_UNAVAILABLE) {
            headers.set(HttpHeaders.RETRY_AFTER, "5");
        }
        return headers;
    }

    private static ProblemDetail problem(HttpServletRequest request, HttpStatus status) {
        String detail = switch (status) {
            case UNAUTHORIZED -> "Authentication is required or the supplied credentials are invalid.";
            case FORBIDDEN -> "You do not have permission to perform this operation.";
            case TOO_MANY_REQUESTS -> "Too many authentication requests. Retry after the indicated delay.";
            case PAYLOAD_TOO_LARGE -> "The request body exceeds the permitted size.";
            case CONFLICT -> "The resource changed since it was read. Reload it and retry the operation.";
            default -> "A required service is temporarily unavailable.";
        };
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create("about:blank"));
        problem.setTitle(status.getReasonPhrase());
        try {
            // Do not include query parameters: they may contain credentials or personal information.
            problem.setInstance(URI.create(request.getRequestURI()));
        } catch (IllegalArgumentException invalidRequestUri) {
            problem.setInstance(URI.create("/"));
        }
        return problem;
    }
}
