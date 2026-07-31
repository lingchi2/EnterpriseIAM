package com.enterpriseiam.resource;

import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Separate proxy is intentional: the facade starts a transaction before method security runs.
 * Authorization locks the row and the same transaction holds that lock through execution.
 */
@Service
@Transactional(propagation = Propagation.MANDATORY)
public class ResourceOperations {
    private final ResourceRepository resources;

    public ResourceOperations(ResourceRepository resources) {
        this.resources = resources;
    }

    @PreAuthorize("hasPermission(#resource, 'READ')")
    public ResourceSnapshot read(ResourceReference resource) {
        return ResourceSnapshot.from(requireResource(resource));
    }

    @PreAuthorize("hasPermission(#resource, 'WRITE')")
    public ResourceSnapshot write(ResourceReference resource, String content, long expectedVersion) {
        SecuredResource entity = requireResource(resource);
        if (entity.getVersion() != expectedVersion) {
            throw new ObjectOptimisticLockingFailureException(SecuredResource.class, resource.id());
        }
        entity.replaceContent(content);
        resources.flush();
        return ResourceSnapshot.from(entity);
    }

    private SecuredResource requireResource(ResourceReference resource) {
        // Permission resolution has already loaded and locked this entity in this persistence context.
        return resources.findById(resource.id()).orElseThrow(() -> new AccessDeniedException("Access denied"));
    }
}
