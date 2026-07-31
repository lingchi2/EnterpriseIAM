package com.enterpriseiam.resource;

import java.util.UUID;

/** The only client-supplied resource attribute accepted by the authorization boundary. */
public record ResourceReference(UUID id) { }
