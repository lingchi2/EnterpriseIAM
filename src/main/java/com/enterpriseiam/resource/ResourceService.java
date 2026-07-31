package com.enterpriseiam.resource;

import com.enterpriseiam.audit.annotation.AuditAction;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Public entry point. Even reads use a transaction capable of acquiring a PostgreSQL row lock.
 * A caller's existing transaction retains its own timeout; repository query hints still bound waits.
 */
@Service
@Transactional(timeout = 5)
public class ResourceService {
    private final ResourceOperations securedOperations;

    public ResourceService(ResourceOperations securedOperations) {
        this.securedOperations = securedOperations;
    }

    @AuditAction(action = "RESOURCE_READ")
    public ResourceSnapshot read(ResourceReference resource) {
        return securedOperations.read(resource);
    }

    @AuditAction(action = "RESOURCE_WRITE")
    public ResourceSnapshot write(ResourceReference resource, String content, long expectedVersion) {
        return securedOperations.write(resource, content, expectedVersion);
    }
}
