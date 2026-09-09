package com.enterpriseiam.authorization;

import java.util.UUID;

/** Authoritative database attributes; caller-supplied metadata is never used to populate this. */
public record ResourceAttributes(UUID id, UUID ownerId, String department, short classification) { }
