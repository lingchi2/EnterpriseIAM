package com.enterpriseiam.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.proxy.HibernateProxy;

/** Shared identity and optimistic concurrency metadata for database-backed entities. */
@MappedSuperclass
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    @Column(nullable = false)
    private Long version;

    /**
     * Two transient instances are distinct. Persisted identity works across proxy and detached
     * instances without initializing a Hibernate proxy.
     */
    @Override
    public final boolean equals(Object candidate) {
        if (this == candidate) {
            return true;
        }
        if (candidate == null || persistentClass(this) != persistentClass(candidate)) {
            return false;
        }
        UUID identifier = identifier(this);
        return identifier != null && identifier.equals(identifier((BaseEntity) candidate));
    }

    /**
     * A class-based hash is intentional: assigning an ID must never break a HashSet containing an
     * entity. Role and permission sets are bounded authorization graphs, not bulk lookup indexes.
     */
    @Override
    public final int hashCode() {
        return persistentClass(this).hashCode();
    }

    /** Avoid credentials, personal attributes, and lazy associations in diagnostic output. */
    @Override
    public final String toString() {
        return persistentClass(this).getSimpleName() + "[id=" + identifier(this) + "]";
    }

    private static Class<?> persistentClass(Object instance) {
        if (instance instanceof HibernateProxy proxy) {
            return proxy.getHibernateLazyInitializer().getPersistentClass();
        }
        return instance.getClass();
    }

    private static UUID identifier(BaseEntity entity) {
        if (entity instanceof HibernateProxy proxy) {
            // Unlike getIdentifier(), this also avoids initialization with JPA proxy compliance on.
            return (UUID) proxy.getHibernateLazyInitializer().getInternalIdentifier();
        }
        return entity.id;
    }
}
