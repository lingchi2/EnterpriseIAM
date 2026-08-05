package com.enterpriseiam.security.identity;

import java.security.Principal;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/** A credential-free, immutable snapshot of authoritative account attributes. */
public record IamPrincipal(UUID userId, String email, String department,
        short clearanceLevel, Set<String> roles, Set<String> permissions) implements Principal {

    public IamPrincipal {
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(email, "email");
        Objects.requireNonNull(department, "department");
        if (clearanceLevel < 0 || clearanceLevel > 4) {
            throw new IllegalArgumentException("Invalid clearance level");
        }
        roles = Set.copyOf(roles);
        permissions = Set.copyOf(permissions);
    }

    public Collection<? extends GrantedAuthority> authorities() {
        // Separate namespaces: a permission called ROLE_ADMIN must never confer an ADMIN role.
        return Stream.concat(roles.stream().map(role -> "ROLE_" + role),
                        permissions.stream().map(permission -> "PERM_" + permission))
                .sorted().map(SimpleGrantedAuthority::new).toList();
    }

    @Override
    public String getName() {
        return userId.toString();
    }

    @Override
    public String toString() {
        return "IamPrincipal[userId=" + userId + "]";
    }
}
