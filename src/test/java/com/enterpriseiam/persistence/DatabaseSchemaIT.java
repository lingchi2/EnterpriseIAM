package com.enterpriseiam.persistence;

import com.enterpriseiam.identity.domain.Permission;
import com.enterpriseiam.identity.domain.Role;
import com.enterpriseiam.identity.domain.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.OptimisticLockException;
import java.sql.Savepoint;
import java.sql.SQLException;
import java.util.UUID;
import org.hibernate.Hibernate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the actual Flyway migration and Hibernate mappings against PostgreSQL.
 * Run with {@code mvn -Pintegration verify}. Docker is required by default; tests
 * never silently skip. An explicitly supplied {@code IAM_TEST_DB_URL}, username,
 * and password can instead target a disposable PostgreSQL test database. Flyway
 * creates and changes its schema, so this must never target production data.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class DatabaseSchemaIT {

    private static final String ENCODED_PASSWORD =
            "{bcrypt}$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";

    private static PostgreSQLContainer<?> postgres;

    @DynamicPropertySource
    static synchronized void databaseProperties(DynamicPropertyRegistry registry) {
        String url;
        String username;
        String password;
        if (System.getenv("IAM_TEST_DB_URL") != null) {
            url = requiredEnvironment("IAM_TEST_DB_URL");
            username = requiredEnvironment("IAM_TEST_DB_USERNAME");
            password = requiredEnvironment("IAM_TEST_DB_PASSWORD");
        } else {
            if (postgres == null) {
                postgres = new PostgreSQLContainer<>("postgres:16.9-alpine")
                        .withDatabaseName("enterpriseiam_test")
                        .withUsername("iam_test")
                        .withPassword("test-only-password");
                postgres.start();
            }
            url = postgres.getJdbcUrl();
            username = postgres.getUsername();
            password = postgres.getPassword();
        }
        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", () -> username);
        registry.add("spring.datasource.password", () -> password);
        registry.add("spring.flyway.url", () -> url);
        registry.add("spring.flyway.user", () -> username);
        registry.add("spring.flyway.password", () -> password);
        registry.add("spring.flyway.default-schema", () -> "iam");
        registry.add("spring.flyway.schemas", () -> "iam");
        registry.add("spring.jpa.properties.hibernate.default_schema", () -> "iam");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
    }

    @AfterAll
    static void stopContainer() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for an external disposable test database");
        }
        return value;
    }

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Test
    void persistsAndReloadsTheAuthorizationGraphUsingTheMigratedSchema() {
        Permission permission = Permission.create("SCHEMA_TEST:READ");
        Role role = Role.create("ANALYST");
        role.grantPermission(permission);
        User user = User.register("  Analyst@Example.com  ", ENCODED_PASSWORD,
                "Security", (short) 2);
        user.assignRole(role);

        entityManager.persist(permission);
        entityManager.persist(role);
        entityManager.persist(user);
        entityManager.flush();
        entityManager.clear();

        User proxy = entityManager.getReference(User.class, user.getId());
        assertFalse(Hibernate.isInitialized(proxy));
        assertEquals(user, proxy);
        assertEquals(proxy, user);
        assertEquals(user.hashCode(), proxy.hashCode());
        assertFalse(Hibernate.isInitialized(proxy),
                "Identity comparisons must not initialize a Hibernate proxy");

        User reloaded = entityManager.find(User.class, user.getId());
        assertEquals("analyst@example.com", reloaded.getEmail());
        assertEquals((short) 2, reloaded.getClearanceLevel());
        assertEquals("PENDING_VERIFICATION", reloaded.getStatus().name());
        assertNotNull(reloaded.getCreatedAt());
        assertNotNull(reloaded.getUpdatedAt());
        assertEquals(0L, reloaded.getVersion());
        assertEquals(1, reloaded.getRoles().size());
        Role reloadedRole = reloaded.getRoles().iterator().next();
        assertEquals("ANALYST", reloadedRole.getName());
        assertEquals("SCHEMA_TEST:READ",
                reloadedRole.getPermissions().iterator().next().getName());
    }

    @Test
    void enforcesCanonicalUniqueIdentitiesAndEncodedPasswordStorage() {
        insertUser("alice@example.com");

        expectConstraintViolation("23505", () -> insertUser("alice@example.com"));
        expectConstraintViolation("23514", () -> insertUser("Alice@example.com"));
        expectConstraintViolation("23514", () -> insertUser(" alice@example.com "));
        expectConstraintViolation("23514", () -> insertUser("invalid-address"));
        expectConstraintViolation("23514", () -> jdbc.update("""
                UPDATE iam.users SET password_hash = ? WHERE email = ?
                """, "plaintext", "alice@example.com"));
        expectConstraintViolation("23514", () -> jdbc.update("""
                UPDATE iam.users SET password_hash = ? WHERE email = ?
                """, "{noop}plaintext", "alice@example.com"));
    }

    @Test
    void constrainsAuthorizationAttributesAndNamesAtTheDatabaseBoundary() {
        UUID userId = insertUser("alice@example.com");
        expectConstraintViolation("23514", () -> jdbc.update(
                "UPDATE iam.users SET clearance_level = 5 WHERE id = ?", userId));
        expectConstraintViolation("23514", () -> jdbc.update(
                "UPDATE iam.users SET department = ' ' WHERE id = ?", userId));
        expectConstraintViolation("23514", () -> jdbc.update(
                "UPDATE iam.users SET status = 'UNKNOWN' WHERE id = ?", userId));
        expectConstraintViolation("23514", () -> jdbc.update(
                "UPDATE iam.users SET version = -1 WHERE id = ?", userId));
        expectConstraintViolation("23514", () -> jdbc.update(
                "INSERT INTO iam.roles (id, name) VALUES (?, ?)", UUID.randomUUID(), "admin"));
        expectConstraintViolation("23514", () -> jdbc.update(
                "INSERT INTO iam.permissions (id, name) VALUES (?, ?)",
                UUID.randomUUID(), "RESOURCE::READ"));
    }

    @Test
    void removesUserMembershipsWithoutDeletingSharedAuthorizationDefinitions() {
        UUID userId = insertUser("alice@example.com");
        UUID roleId = UUID.randomUUID();
        UUID permissionId = UUID.randomUUID();
        jdbc.update("INSERT INTO iam.roles (id, name) VALUES (?, 'ANALYST')", roleId);
        jdbc.update("INSERT INTO iam.permissions (id, name) VALUES (?, 'SCHEMA_TEST:READ')",
                permissionId);
        jdbc.update("INSERT INTO iam.user_roles (user_id, role_id) VALUES (?, ?)", userId, roleId);
        jdbc.update("INSERT INTO iam.role_permissions (role_id, permission_id) VALUES (?, ?)",
                roleId, permissionId);

        expectConstraintViolation("23505", () -> jdbc.update(
                "INSERT INTO iam.user_roles (user_id, role_id) VALUES (?, ?)", userId, roleId));
        expectConstraintViolation("23503", () -> jdbc.update(
                "DELETE FROM iam.roles WHERE id = ?", roleId));
        expectConstraintViolation("23503", () -> jdbc.update(
                "DELETE FROM iam.permissions WHERE id = ?", permissionId));

        jdbc.update("DELETE FROM iam.users WHERE id = ?", userId);
        assertEquals(0, jdbc.queryForObject(
                "SELECT count(*) FROM iam.user_roles WHERE user_id = ?", Integer.class, userId));
        assertEquals(1, jdbc.queryForObject(
                "SELECT count(*) FROM iam.roles WHERE id = ?", Integer.class, roleId));
        assertEquals(1, jdbc.queryForObject(
                "SELECT count(*) FROM iam.permissions WHERE id = ?", Integer.class, permissionId));
        expectConstraintViolation("23503", () -> jdbc.update(
                "DELETE FROM iam.roles WHERE id = ?", roleId));
    }

    @Test
    void rejectsRawRefreshTokensExpiredLifetimesAndInconsistentRevocation() {
        UUID userId = insertUser("alice@example.com");
        UUID tokenId = insertToken(userId, UUID.randomUUID(), "a".repeat(64));

        expectConstraintViolation("23505", () -> insertToken(
                userId, UUID.randomUUID(), "a".repeat(64)));
        expectConstraintViolation("23514", () -> insertToken(
                userId, UUID.randomUUID(), "a-raw-refresh-token"));
        expectConstraintViolation("23514", () -> jdbc.update(
                "UPDATE iam.refresh_tokens SET expires_at = created_at WHERE id = ?", tokenId));
        expectConstraintViolation("23514", () -> jdbc.update(
                "UPDATE iam.refresh_tokens SET revoked = true WHERE id = ?", tokenId));
        expectConstraintViolation("23514", () -> jdbc.update(
                "UPDATE iam.refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?", tokenId));
        expectConstraintViolation("23514", () -> jdbc.update("""
                UPDATE iam.refresh_tokens
                SET revoked = true, revoked_at = created_at - INTERVAL '1 second'
                WHERE id = ?
                """, tokenId));
    }

    @Test
    void rotationLinksOnlyRevokedTokensToSuccessorsInTheSameUserAndFamily() {
        UUID userId = insertUser("alice@example.com");
        UUID otherUserId = insertUser("bob@example.com");
        UUID familyId = UUID.randomUUID();
        UUID originalId = insertToken(userId, familyId, "a".repeat(64));
        UUID successorId = insertToken(userId, familyId, "b".repeat(64));
        UUID otherFamilyTokenId = insertToken(userId, UUID.randomUUID(), "c".repeat(64));
        UUID otherUserTokenId = insertToken(otherUserId, UUID.randomUUID(), "d".repeat(64));

        expectConstraintViolation("23514", () -> jdbc.update(
                "UPDATE iam.refresh_tokens SET replaced_by_token_id = ? WHERE id = ?",
                successorId, originalId));
        expectConstraintViolation("23514", () -> revokeAndReplace(originalId, originalId));
        expectConstraintViolation("23503", () -> revokeAndReplace(originalId, otherFamilyTokenId));
        expectConstraintViolation("23503", () -> revokeAndReplace(originalId, otherUserTokenId));

        revokeAndReplace(originalId, successorId);
        assertTrue(Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT revoked FROM iam.refresh_tokens WHERE id = ?", Boolean.class, originalId)));
        assertFalse(Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT revoked FROM iam.refresh_tokens WHERE id = ?", Boolean.class, successorId)));
        expectConstraintViolation("23503", () -> jdbc.update(
                "DELETE FROM iam.refresh_tokens WHERE id = ?", successorId));

        // User deletion removes the complete chain, including self-references.
        jdbc.update("DELETE FROM iam.users WHERE id = ?", userId);
        assertEquals(0, jdbc.queryForObject(
                "SELECT count(*) FROM iam.refresh_tokens WHERE user_id = ?", Integer.class, userId));
        assertEquals(1, jdbc.queryForObject(
                "SELECT count(*) FROM iam.refresh_tokens WHERE user_id = ?", Integer.class, otherUserId));
    }

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void optimisticLockingRejectsConcurrentAttributeUpdates() {
        User user = User.register("concurrent@example.com", ENCODED_PASSWORD, "Security", (short) 2);
        EntityManager first = entityManagerFactory.createEntityManager();
        EntityManager second = entityManagerFactory.createEntityManager();
        try {
            first.getTransaction().begin();
            first.persist(user);
            first.getTransaction().commit();
            first.clear();

            first.getTransaction().begin();
            User firstCopy = first.find(User.class, user.getId());
            second.getTransaction().begin();
            User secondCopy = second.find(User.class, user.getId());

            firstCopy.updateAttributes("Operations", (short) 3);
            first.getTransaction().commit();
            secondCopy.updateAttributes("Finance", (short) 1);
            assertThrows(OptimisticLockException.class, second::flush);
        } finally {
            if (first.getTransaction().isActive()) {
                first.getTransaction().rollback();
            }
            if (second.getTransaction().isActive()) {
                second.getTransaction().rollback();
            }
            first.close();
            second.close();
            if (user.getId() != null) {
                jdbc.update("DELETE FROM iam.users WHERE id = ?", user.getId());
            }
        }
    }

    private UUID insertUser(String email) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO iam.users (id, email, password_hash, department, clearance_level)
                VALUES (?, ?, ?, 'Security', 2)
                """, id, email, ENCODED_PASSWORD);
        return id;
    }

    private UUID insertToken(UUID userId, UUID familyId, String tokenHash) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO iam.auth_sessions (id, user_id, created_at, expires_at)
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '30 days')
                ON CONFLICT (id) DO NOTHING
                """, familyId, userId);
        jdbc.update("""
                INSERT INTO iam.refresh_tokens (id, user_id, token_hash, family_id, expires_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP + INTERVAL '30 days')
                """, id, userId, tokenHash, familyId);
        return id;
    }

    private void revokeAndReplace(UUID tokenId, UUID successorId) {
        jdbc.update("""
                UPDATE iam.refresh_tokens
                SET revoked = true, revoked_at = CURRENT_TIMESTAMP, replaced_by_token_id = ?,
                    version = version + 1
                WHERE id = ?
                """, successorId, tokenId);
    }

    /** Recover PostgreSQL's transaction after each intentionally rejected statement. */
    private void expectConstraintViolation(String sqlState, Runnable operation) {
        Savepoint savepoint = jdbc.execute((ConnectionCallback<Savepoint>) connection -> connection.setSavepoint());
        try {
            DataIntegrityViolationException exception =
                    assertThrows(DataIntegrityViolationException.class, operation::run);
            Throwable root = exception.getMostSpecificCause();
            assertTrue(root instanceof SQLException, "Expected a PostgreSQL constraint violation");
            assertEquals(sqlState, ((SQLException) root).getSQLState());
        } finally {
            jdbc.execute((ConnectionCallback<Void>) connection -> {
                connection.rollback(savepoint);
                connection.releaseSavepoint(savepoint);
                return null;
            });
        }
    }
}
