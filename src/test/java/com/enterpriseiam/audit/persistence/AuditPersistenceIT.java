package com.enterpriseiam.audit.persistence;

import com.enterpriseiam.audit.model.AuditEvent;
import com.enterpriseiam.audit.model.AuditPhase;
import com.enterpriseiam.identity.domain.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.EntityManager;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import static org.junit.jupiter.api.Assertions.*;

/** Uses the actual JpaTransactionManager shared by business entities and JDBC audit inserts. */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditRecorder.class, AuditDeliveryStore.class, AuditPersistenceIT.Configuration.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuditPersistenceIT {
    private static PostgreSQLContainer<?> postgres;
    @Autowired private AuditRecorder recorder;
    @Autowired private AuditDeliveryStore store;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private EntityManager entityManager;
    @Autowired private PlatformTransactionManager manager;
    @Autowired private CommitProbe committed;

    @DynamicPropertySource
    static synchronized void database(DynamicPropertyRegistry registry) {
        String url;
        String username;
        String password;
        if (System.getenv("IAM_TEST_DB_URL") != null) {
            url = environment("IAM_TEST_DB_URL");
            username = environment("IAM_TEST_DB_USERNAME");
            password = environment("IAM_TEST_DB_PASSWORD");
        } else {
            postgres = new PostgreSQLContainer<>("postgres:16.9-alpine")
                    .withDatabaseName("enterpriseiam_audit_test").withUsername("iam_test")
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
    }

    @AfterAll
    static void stopDatabase() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    @BeforeEach
    void isolatePendingDeliveryFixtures() {
        // Only a disposable integration database is permitted. Retain immutable event rows,
        // but acknowledge pending fixtures from previous tests/runs before testing claims.
        jdbc.update("UPDATE iam.audit_delivery SET delivered_at = clock_timestamp(), lease_token = NULL, lease_until = NULL WHERE delivered_at IS NULL");
        committed.count.set(0);
    }

    @Test
    void idempotentReplayVerifiesTheExactPayloadAndKeepsOneDeliveryRow() {
        AuditEvent event = event(UUID.randomUUID(), "RESOURCE_READ");
        recorder.appendIndependent(event);
        recorder.appendIndependent(event);
        assertEquals(1, countEvent(event));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM iam.audit_delivery WHERE event_id = ?",
                Integer.class, event.id()));
        assertTrue(jdbc.queryForObject("SELECT payload_sha256 FROM iam.audit_events WHERE id = ?",
                String.class, event.id()).matches("[0-9a-f]{64}"));
    }

    @Test
    void reusingAnEventUuidForDifferentDataFailsClosedAndPreservesOriginal() {
        UUID id = UUID.randomUUID();
        AuditEvent original = event(id, "RESOURCE_READ");
        recorder.appendIndependent(original);
        assertThrows(AuditUnavailableException.class,
                () -> recorder.appendIndependent(event(id, "RESOURCE_UPDATE")));
        assertEquals("RESOURCE_READ", jdbc.queryForObject(
                "SELECT payload ->> 'action' FROM iam.audit_events WHERE id = ?", String.class, id));
    }

    @Test
    void databaseRejectsUpdateDeleteAndTruncateOfTheAuditLedger() {
        AuditEvent event = event(UUID.randomUUID(), "RESOURCE_READ");
        recorder.appendIndependent(event);
        assertConstraint(() -> jdbc.update("UPDATE iam.audit_events SET payload_sha256 = ? WHERE id = ?",
                "0".repeat(64), event.id()));
        assertConstraint(() -> jdbc.update("DELETE FROM iam.audit_events WHERE id = ?", event.id()));
        assertConstraint(() -> jdbc.execute("TRUNCATE iam.audit_events CASCADE"));
        assertEquals(1, countEvent(event));
    }

    @Test
    void businessAndSuccessAuditRowsShareTheSameJpaTransactionAndRollbackTogether() {
        AuditEvent event = event(UUID.randomUUID(), "RESOURCE_UPDATE");
        User user = User.register(UUID.randomUUID() + "@example.com",
                "{bcrypt}$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW", "Security", (short) 1);
        new TransactionTemplate(manager).executeWithoutResult(status -> {
            entityManager.persist(user);
            entityManager.flush();
            recorder.appendInCurrentTransaction(event);
            assertEquals(1, countEvent(event));
            assertEquals(0, committed.count.get());
            status.setRollbackOnly();
        });
        assertEquals(0, countEvent(event));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM iam.users WHERE id = ?", Integer.class, user.getId()));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM iam.audit_delivery WHERE event_id = ?",
                Integer.class, event.id()));
        assertEquals(0, committed.count.get());
    }

    @Test
    void independentAttemptSurvivesAnOuterRollbackAndCommitNotificationWaitsForCommit() {
        AuditEvent attempt = event(UUID.randomUUID(), "AUTH_LOGIN");
        AuditEvent success = event(UUID.randomUUID(), "AUTH_LOGIN");
        new TransactionTemplate(manager).executeWithoutResult(status -> {
            recorder.appendIndependent(attempt);
            assertEquals(1, committed.count.get());
            recorder.appendInCurrentTransaction(success);
            assertEquals(1, committed.count.get());
            status.setRollbackOnly();
        });
        assertEquals(1, countEvent(attempt));
        assertEquals(0, countEvent(success));
        assertEquals(1, committed.count.get());
    }

    @Test
    void ambientCaptureRequiresAnActualTransaction() {
        AuditEvent event = event(UUID.randomUUID(), "RESOURCE_UPDATE");
        assertThrows(AuditUnavailableException.class, () -> recorder.appendInCurrentTransaction(event));
        assertEquals(0, countEvent(event));
    }

    @Test
    void committedSuccessWakesDeliveryOnlyAfterCommit() {
        AuditEvent event = event(UUID.randomUUID(), "RESOURCE_UPDATE");
        new TransactionTemplate(manager).executeWithoutResult(status -> {
            recorder.appendInCurrentTransaction(event);
            assertEquals(0, committed.count.get());
        });
        assertEquals(1, committed.count.get());
        assertEquals(1, countEvent(event));
    }

    @Test
    void concurrentReplicasClaimDisjointBatchesWithoutBlockingEachOther() throws Exception {
        for (int i = 0; i < 20; i++) {
            recorder.appendIndependent(event(UUID.randomUUID(), "RESOURCE_READ"));
        }
        CountDownLatch start = new CountDownLatch(1);
        try (var threads = Executors.newFixedThreadPool(4)) {
            var futures = java.util.stream.IntStream.range(0, 4).mapToObj(ignored -> threads.submit(() -> {
                assertTrue(start.await(10, TimeUnit.SECONDS));
                return store.claimBatch(5, Duration.ofSeconds(60));
            })).toList();
            start.countDown();
            HashSet<UUID> claimed = new HashSet<>();
            for (var future : futures) {
                List<AuditDeliveryStore.Claim> batch = future.get(20, TimeUnit.SECONDS);
                assertEquals(5, batch.size());
                batch.forEach(claim -> assertTrue(claimed.add(claim.eventId()), "An event was claimed twice"));
            }
            assertEquals(20, claimed.size());
            assertTrue(store.claimBatch(1, Duration.ofSeconds(60)).isEmpty());
        }
    }

    @Test
    void expiredLeaseCanBeReclaimedAndStaleWorkerCannotCompleteOrRescheduleIt() {
        AuditEvent event = event(UUID.randomUUID(), "RESOURCE_READ");
        recorder.appendIndependent(event);
        AuditDeliveryStore.Claim first = store.claimBatch(1, Duration.ofSeconds(60)).getFirst();
        jdbc.update("UPDATE iam.audit_delivery SET lease_until = clock_timestamp() - INTERVAL '1 second' WHERE event_id = ?", event.id());
        AuditDeliveryStore.Claim second = store.claimBatch(1, Duration.ofSeconds(60)).getFirst();
        assertNotEquals(first.leaseToken(), second.leaseToken());
        assertEquals(2, second.attempts());
        assertFalse(store.complete(first));
        assertFalse(store.retry(first, Duration.ofSeconds(5), "DELIVERY_FAILED"));
        assertFalse(store.renew(first, Duration.ofSeconds(60)));
        assertTrue(store.renew(second, Duration.ofSeconds(60)));
        assertTrue(store.complete(second));
        assertTrue(store.claimBatch(1, Duration.ofSeconds(60)).isEmpty());
        assertEquals(1, countEvent(event), "Delivered events must remain in the immutable ledger");
    }

    @Test
    void retriesRespectBackoffAndRemainClaimableAfterAnyNumberOfFailures() {
        AuditEvent event = event(UUID.randomUUID(), "RESOURCE_READ");
        recorder.appendIndependent(event);
        AuditDeliveryStore.Claim claim = store.claimBatch(1, Duration.ofSeconds(60)).getFirst();
        assertTrue(store.retry(claim, Duration.ofHours(1), "DELIVERY_FAILED"));
        assertTrue(store.claimBatch(1, Duration.ofSeconds(60)).isEmpty());
        jdbc.update("""
                UPDATE iam.audit_delivery SET attempts = 9223372036854775807,
                    next_attempt_at = clock_timestamp() - INTERVAL '1 second'
                WHERE event_id = ?
                """, event.id());
        AuditDeliveryStore.Claim retried = store.claimBatch(1, Duration.ofSeconds(60)).getFirst();
        assertEquals(Long.MAX_VALUE, retried.attempts());
        assertEquals(event.id(), retried.eventId());
    }

    private int countEvent(AuditEvent event) {
        return jdbc.queryForObject("SELECT count(*) FROM iam.audit_events WHERE id = ?", Integer.class, event.id());
    }

    private static AuditEvent event(UUID id, String action) {
        return new AuditEvent(id, UUID.randomUUID(), Instant.now(), action, AuditPhase.SUCCEEDED,
                "anonymous", "Test.operation", Map.of("safeId", UUID.randomUUID().toString()),
                "127.0.0.1", "test", "POST", "/api/v1/resources", "SUCCESS");
    }

    private static void assertConstraint(Runnable operation) {
        DataIntegrityViolationException failure = assertThrows(DataIntegrityViolationException.class, operation::run);
        assertEquals("23514", ((SQLException) failure.getMostSpecificCause()).getSQLState());
    }

    private static String environment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for a disposable external test database");
        }
        return value;
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class Configuration {
        @Bean ObjectMapper auditMapper() { return new ObjectMapper().registerModule(new JavaTimeModule()); }
        @Bean CommitProbe commitProbe() { return new CommitProbe(); }
    }

    static class CommitProbe {
        private final AtomicInteger count = new AtomicInteger();
        @TransactionalEventListener
        public void onCommit(AuditPendingEvent ignored) { count.incrementAndGet(); }
    }
}
