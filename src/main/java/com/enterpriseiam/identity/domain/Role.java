package com.enterpriseiam.identity.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * An independently managed RBAC role with an immutable name. Permission deletion never cascades
 * from this entity.
 */
@Entity
@Table(name = "roles")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Role extends BaseEntity {

    @Getter
    @Column(nullable = false, unique = true, length = 64)
    private String name;

    @JsonIgnore
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "role_permissions",
            joinColumns = @JoinColumn(name = "role_id", nullable = false),
            inverseJoinColumns = @JoinColumn(name = "permission_id", nullable = false))
    private Set<Permission> permissions = new HashSet<>();

    private Role(String name) {
        this.name = DomainConstraints.roleName(name);
    }

    public static Role create(String name) {
        return new Role(name);
    }

    /** A read-only live view of this role's assigned permissions. */
    @JsonIgnore
    public Set<Permission> getPermissions() {
        return Collections.unmodifiableSet(permissions);
    }

    /** Use an existing managed permission when persisting this assignment. */
    public boolean grantPermission(Permission permission) {
        return permissions.add(Objects.requireNonNull(permission, "permission is required"));
    }

    public boolean revokePermission(Permission permission) {
        return permissions.remove(Objects.requireNonNull(permission, "permission is required"));
    }
}
