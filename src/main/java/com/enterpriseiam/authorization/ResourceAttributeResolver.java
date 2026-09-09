package com.enterpriseiam.authorization;

import com.enterpriseiam.resource.ResourceRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Component
public class ResourceAttributeResolver {
    private final ResourceRepository resources;
    private final EntityManager entityManager;

    public ResourceAttributeResolver(ResourceRepository resources, EntityManager entityManager) {
        this.resources = resources;
        this.entityManager = entityManager;
    }

    public Optional<ResourceAttributes> resolve(UUID id, ResourceAction action) {
        // Releasing the lock before the protected operation would permit a metadata race.
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            return Optional.empty();
        }
        var resource = action == ResourceAction.READ ? resources.findForRead(id) : resources.findForWrite(id);
        return resource.map(entity -> {
            // Also refresh an entity that an outer transaction loaded before the lock was acquired.
            // A locked JPQL query alone may otherwise return stale first-level-cache attributes.
            // Call the ResourceService boundary before modifying managed resources: authorization
            // intentionally trusts persisted state, and refresh replaces cached entity values.
            entityManager.refresh(entity, action == ResourceAction.READ
                    ? LockModeType.PESSIMISTIC_READ : LockModeType.PESSIMISTIC_WRITE);
            return new ResourceAttributes(entity.getId(), entity.getOwnerId(),
                    entity.getDepartment(), entity.getClassification());
        });
    }
}
