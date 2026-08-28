package com.enterpriseiam.security.web;

import com.enterpriseiam.api.web.RequestBodyTooLargeException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.transaction.TransactionException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

@RestControllerAdvice
public class SecurityExceptionHandler extends ResponseEntityExceptionHandler {
    private final SecurityProblemSupport problems;

    public SecurityExceptionHandler(SecurityProblemSupport problems) { this.problems = problems; }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException exception,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        if (RequestBodyTooLargeException.causedBy(exception) && request instanceof ServletWebRequest servlet) {
            ResponseEntity<ProblemDetail> response = problems.response(servlet.getRequest(), HttpStatus.PAYLOAD_TOO_LARGE);
            return new ResponseEntity<>(response.getBody(), response.getHeaders(), response.getStatusCode());
        }
        return super.handleHttpMessageNotReadable(exception, headers, status, request);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ProblemDetail> authentication(AuthenticationException exception,
            HttpServletRequest request) {
        return problems.response(request, problems.status(exception));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> forbidden(AccessDeniedException exception, HttpServletRequest request) {
        return problems.response(request, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler({DataAccessException.class, TransactionException.class})
    public ResponseEntity<ProblemDetail> dependencyUnavailable(RuntimeException exception,
            HttpServletRequest request) {
        return problems.response(request, HttpStatus.SERVICE_UNAVAILABLE);
    }

    @ExceptionHandler(OptimisticLockingFailureException.class)
    public ResponseEntity<ProblemDetail> concurrentModification(OptimisticLockingFailureException exception,
            HttpServletRequest request) {
        return problems.response(request, HttpStatus.CONFLICT);
    }
}
