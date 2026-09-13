package com.enterpriseiam.api.resource;

import java.util.UUID;

public record ResourceResponse(UUID id, UUID ownerId, String department, short classification,
        String content, long version) {
    @Override
    public String toString() {
        return "ResourceResponse[id=" + id + ", content=[REDACTED], version=" + version + "]";
    }
}
