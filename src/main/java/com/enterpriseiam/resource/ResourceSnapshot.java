package com.enterpriseiam.resource;

import java.util.UUID;

/** Immutable return value; managed entities never leave the service boundary. */
public record ResourceSnapshot(UUID id, UUID ownerId, String department, short classification,
        String content, long version) {
    static ResourceSnapshot from(SecuredResource resource) {
        return new ResourceSnapshot(resource.getId(), resource.getOwnerId(), resource.getDepartment(),
                resource.getClassification(), resource.getContent(), resource.getVersion());
    }
}
