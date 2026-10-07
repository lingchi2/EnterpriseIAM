package com.enterpriseiam.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.enterpriseiam.authorization.AbacPermissionEvaluator;
import com.enterpriseiam.authorization.DefaultAbacPolicy;
import com.enterpriseiam.authorization.EnvironmentAttributeResolver;
import com.enterpriseiam.authorization.MethodSecurityConfiguration;
import com.enterpriseiam.authorization.ResourceAttributeResolver;
import com.enterpriseiam.authorization.SubjectAttributeResolver;
import com.enterpriseiam.security.identity.IamPrincipal;
import com.enterpriseiam.security.identity.IdentityDirectory;
import jakarta.persistence.EntityManager;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.testcontainers.containers.PostgreSQLContainer;

/** Real PostgreSQL migration, method-security proxies, live identity reads and locking semantics. */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@TestPropertySource(properties = "iam.abac.allowed-cidrs=10.0.0.0/8")
@Import({ResourceService.class, ResourceOperations.class, ResourceAttributeResolver.class,
        SubjectAttributeResolver.class, EnvironmentAttributeResolver.class, AbacPermissionEvaluator.class,
        DefaultAbacPolicy.class, MethodSecurityConfiguration.class, IdentityDirectory.class,
        ResourceAuthorizationIT.TestClock.class})
class ResourceAuthorizationIT {
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
            postgres = new PostgreSQLContainer<>("postgres:16.9-alpine")
                    .withDatabaseName("enterpriseiam_resource_test").withUsername("iam_test")
                    .withPassword("test-only-password");
            postgres.start();
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

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for a disposable external test database");
        }
        return value;
    }

    @AfterAll
    static void stopContainer() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    @Autowired ResourceService service;
    @Autowired ResourceRepository resources;
    @Autowired IdentityDirectory identities;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactionManager;
    @Autowired EntityManager entityManager;
    private UUID userId;
    private UUID roleId;
    private ResourceReference reference;

    @BeforeEach
    void seed() {
        userId = UUID.randomUUID();
        roleId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO iam.users (id, email, password_hash, status, department, clearance_level)
                VALUES (?, ?, '{bcrypt}test-only-encoded', 'ACTIVE', 'Engineering', 2)
                """, userId, userId + "@example.com");
        jdbc.update("INSERT INTO iam.roles (id, name) VALUES (?, ?)", roleId,
                "RESOURCE_TEST_" + roleId.toString().replace("-", "").toUpperCase(java.util.Locale.ROOT));
        jdbc.update("INSERT INTO iam.user_roles (user_id, role_id) VALUES (?, ?)", userId, roleId);
        for (String permission : new String[]{"RESOURCE:READ", "RESOURCE:WRITE"}) {
            jdbc.update("INSERT INTO iam.permissions (id, name) VALUES (?, ?) ON CONFLICT (name) DO NOTHING",
                    UUID.randomUUID(), permission);
            jdbc.update("""
                    INSERT INTO iam.role_permissions (role_id, permission_id)
                    SELECT ?, id FROM iam.permissions WHERE name = ?
                    """, roleId, permission);
        }
        reference = new TransactionTemplate(transactionManager).execute(status -> new ResourceReference(
                resources.saveAndFlush(SecuredResource.create(userId, "Engineering", (short) 2, "original")).getId()));
        IamPrincipal principal = identities.requireActive(userId);
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.authorities()));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.1.2.3");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void cleanUp() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
        if (userId != null) {
            jdbc.update("DELETE FROM iam.secured_resources WHERE owner_id = ?", userId);
            jdbc.update("DELETE FROM iam.users WHERE id = ?", userId);
        }
        if (roleId != null) {
            jdbc.update("DELETE FROM iam.role_permissions WHERE role_id = ?", roleId);
            jdbc.update("DELETE FROM iam.roles WHERE id = ?", roleId);
        }
        jdbc.update("""
                DELETE FROM iam.permissions permission
                WHERE permission.name IN ('RESOURCE:READ', 'RESOURCE:WRITE')
                AND NOT EXISTS (SELECT 1 FROM iam.role_permissions rp WHERE rp.permission_id = permission.id)
                """);
    }

    @Test
    void authorizedReadWriteAndVersionCheckUseMigratedPersistence() {
        assertThat(service.read(reference).content()).isEqualTo("original");
        var saved = service.write(reference, "updated", 0);
        assertThat(saved.version()).isEqualTo(1);
        assertThat(saved.content()).isEqualTo("updated");
        assertThat(service.read(reference).content()).isEqualTo("updated");
        assertThatThrownBy(() -> service.write(reference, "lost update", 0))
                .isInstanceOf(ObjectOptimisticLockingFailureException.class);
        assertThat(service.read(reference).content()).isEqualTo("updated");
    }

    @Test
    void persistedSubjectAttributeChangesInvalidateAlreadyAuthenticatedAccess() {
        assertThat(service.read(reference).content()).isEqualTo("original");
        jdbc.update("UPDATE iam.users SET clearance_level = 1, version = version + 1 WHERE id = ?", userId);
        assertThatThrownBy(() -> service.read(reference)).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> service.write(reference, "forbidden", 0)).isInstanceOf(AccessDeniedException.class);
        assertThat(jdbc.queryForObject("SELECT content FROM iam.secured_resources WHERE id = ?",
                String.class, reference.id())).isEqualTo("original");
    }

    @Test
    void revokedPermissionAndDisabledUserInvalidateAccess() {
        jdbc.update("DELETE FROM iam.role_permissions WHERE role_id = ?", roleId);
        assertThatThrownBy(() -> service.read(reference)).isInstanceOf(AccessDeniedException.class);
        jdbc.update("UPDATE iam.users SET status = 'DISABLED', version = version + 1 WHERE id = ?", userId);
        assertThatThrownBy(() -> service.write(reference, "forbidden", 0)).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void freshlyLockedResourceAttributesReplaceStaleFirstLevelCacheState() {
        assertThatThrownBy(() -> new TransactionTemplate(transactionManager).execute(status -> {
            var stale = entityManager.find(SecuredResource.class, reference.id());
            assertThat(stale.getClassification()).isEqualTo((short) 2);
            jdbc.update("UPDATE iam.secured_resources SET classification = 4 WHERE id = ?", reference.id());
            return service.read(reference);
        })).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void authorizationReadLockBlocksConcurrentResourceMetadataChangesUntilTransactionEnds() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            service.read(reference);
            try (var worker = Executors.newSingleThreadExecutor()) {
                var competingUpdate = worker.submit(() -> new TransactionTemplate(transactionManager)
                        .executeWithoutResult(competing -> {
                            jdbc.execute("SET LOCAL lock_timeout = '150ms'");
                            jdbc.update("UPDATE iam.secured_resources SET classification = 4 WHERE id = ?",
                                    reference.id());
                        }));
                try {
                    competingUpdate.get(5, TimeUnit.SECONDS);
                    org.junit.jupiter.api.Assertions.fail("Metadata update should be blocked by authorization's row lock");
                } catch (ExecutionException exception) {
                    Throwable cause = exception;
                    while (cause.getCause() != null) {
                        cause = cause.getCause();
                    }
                    assertThat(cause).isInstanceOf(SQLException.class);
                    assertThat(((SQLException) cause).getSQLState()).isEqualTo("55P03");
                } catch (Exception exception) {
                    throw new AssertionError("Concurrent update did not complete predictably", exception);
                }
            }
        });
        // Once the operation's transaction ends, another update can acquire the same row.
        assertThat(jdbc.update("UPDATE iam.secured_resources SET classification = 3 WHERE id = ?",
                reference.id())).isEqualTo(1);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class TestClock {
        @Bean Clock clock() {
            return Clock.fixed(Instant.parse("2026-10-23T12:00:00Z"), ZoneOffset.UTC);
        }
    }
}
