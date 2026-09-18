package com.enterpriseiam.audit.persistence;

import org.springframework.security.authentication.AuthenticationServiceException;

/** Fails sensitive operations closed when durable audit capture is unavailable. */
public final class AuditUnavailableException extends AuthenticationServiceException {
    public AuditUnavailableException(String message) {
        super(message);
    }

    public AuditUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public AuditUnavailableException(Throwable cause) {
        super("Audit persistence unavailable", cause);
    }
}
