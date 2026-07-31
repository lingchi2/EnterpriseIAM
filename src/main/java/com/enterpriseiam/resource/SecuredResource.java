package com.enterpriseiam.resource;

import com.enterpriseiam.identity.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.util.Objects;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "secured_resources")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class SecuredResource extends BaseEntity {
    @Column(name = "owner_id", nullable = false, updatable = false)
    private UUID ownerId;

    @Column(nullable = false, length = 100)
    private String department;

    @Column(nullable = false)
    private short classification;

    @Column(nullable = false, columnDefinition = "text")
    private String content;

    public static SecuredResource create(UUID ownerId, String department, short classification, String content) {
        Objects.requireNonNull(ownerId, "Resource owner is required");
        if (department == null || department.isBlank() || department.length() > 100
                || !department.equals(department.trim())) {
            throw new IllegalArgumentException("Resource department must be canonical and at most 100 characters");
        }
        if (classification < 0 || classification > 4) {
            throw new IllegalArgumentException("Resource classification must be between 0 and 4");
        }
        SecuredResource resource = new SecuredResource();
        resource.ownerId = ownerId;
        resource.department = department;
        resource.classification = classification;
        resource.replaceContent(content);
        return resource;
    }

    /** Called only after permission evaluation while holding the database row lock. */
    void replaceContent(String content) {
        if (content == null || content.length() > 1_048_576) {
            throw new IllegalArgumentException("Resource content is required and must not exceed 1048576 characters");
        }
        this.content = content;
    }
}
