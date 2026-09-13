package com.enterpriseiam.api.resource;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

/** Ownership, department, and classification always come from the locked database row. */
public record ResourceUpdateRequest(@NotNull @Size(max = 1_048_576) String content,
        @NotNull @PositiveOrZero Long expectedVersion) {
    @Override
    public String toString() {
        return "ResourceUpdateRequest[content=[REDACTED], expectedVersion=" + expectedVersion + "]";
    }
}
