package com.enterpriseiam.identity.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
 * An account and its role assignments; authentication concerns belong in the security layer.
 * Mutate managed instances inside a transaction so {@code @Version} protects concurrent changes.
 */
@Entity
@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity {

    @Getter
    @Column(nullable = false, unique = true, length = 254)
    private String email;

    @JsonIgnore
    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Getter
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private UserStatus status;

    @Getter
    @Column(nullable = false, length = 100)
    private String department;

    @Getter
    @Column(name = "clearance_level", nullable = false)
    private short clearanceLevel;

    @JsonIgnore
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id", nullable = false),
            inverseJoinColumns = @JoinColumn(name = "role_id", nullable = false))
    private Set<Role> roles = new HashSet<>();

    private User(String email, String encodedPassword, String department, short clearanceLevel) {
        this.email = DomainConstraints.email(email);
        this.passwordHash = DomainConstraints.passwordHash(encodedPassword);
        this.department = DomainConstraints.department(department);
        this.clearanceLevel = DomainConstraints.clearanceLevel(clearanceLevel);
        this.status = UserStatus.PENDING_VERIFICATION;
    }

    /** Caller must supply a password already encoded by the configured password encoder. */
    public static User register(String email, String encodedPassword, String department,
            short clearanceLevel) {
        return new User(email, encodedPassword, department, clearanceLevel);
    }

    @JsonIgnore
    public String getPasswordHash() {
        return passwordHash;
    }

    /** A read-only live view; callers cannot bypass the assignment methods. */
    @JsonIgnore
    public Set<Role> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    public void changeEmail(String email) {
        this.email = DomainConstraints.email(email);
    }

    public void changePasswordHash(String encodedPassword) {
        this.passwordHash = DomainConstraints.passwordHash(encodedPassword);
    }

    /** Validate the complete attribute change before mutating any state. */
    public void updateAttributes(String department, short clearanceLevel) {
        String validatedDepartment = DomainConstraints.department(department);
        short validatedClearance = DomainConstraints.clearanceLevel(clearanceLevel);
        this.department = validatedDepartment;
        this.clearanceLevel = validatedClearance;
    }

    /** Roles have their own lifecycle; use an existing managed role when persisting assignments. */
    public boolean assignRole(Role role) {
        return roles.add(Objects.requireNonNull(role, "role is required"));
    }

    public boolean removeRole(Role role) {
        return roles.remove(Objects.requireNonNull(role, "role is required"));
    }

    /** A verification service must authorize this transition before invoking it. */
    public void activate() {
        requireStatus(UserStatus.PENDING_VERIFICATION);
        this.status = UserStatus.ACTIVE;
    }

    public void lock() {
        requireStatus(UserStatus.ACTIVE);
        this.status = UserStatus.LOCKED;
    }

    public void unlock() {
        requireStatus(UserStatus.LOCKED);
        this.status = UserStatus.ACTIVE;
    }

    public void disable() {
        this.status = UserStatus.DISABLED;
    }

    private void requireStatus(UserStatus required) {
        if (this.status != required) {
            throw new IllegalStateException("Account must be " + required + " for this transition");
        }
    }
}
