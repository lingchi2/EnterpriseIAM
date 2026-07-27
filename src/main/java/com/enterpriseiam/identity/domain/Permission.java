package com.enterpriseiam.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** Immutable permission identifier, such as {@code RESOURCE:READ}. */
@Entity
@Table(name = "permissions")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Permission extends BaseEntity {

    @Getter
    @Column(nullable = false, unique = true, length = 128)
    private String name;

    private Permission(String name) {
        this.name = DomainConstraints.permissionName(name);
    }

    public static Permission create(String name) {
        return new Permission(name);
    }
}
