package com.enterpriseiam.security.tokens;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Tests real PostgreSQL locks and commits; no mocked concurrency or skipped tests. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RefreshTokenServiceIT {

    private static final Duration TTL = Duration.ofDays(30);
    private static final String PASSWORD =
            "{bcrypt}$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";

    private PostgreSQLContainer<?> postgres;
    private HikariDataSource dataSource;
    private JdbcTemplate jdbc;
    private JdbcTransactionManager transactionManager;
    private MutableClock clock;
    private RefreshTokenService service;
    private SessionRegistry sessions;
    private final List<UUID> users = new ArrayList<>();

    @BeforeAll
    void startDatabase() {
        HikariConfig config = new HikariConfig();
        if (System.getenv("IAM_TEST_DB_URL") != null) {
            config.setJdbcUrl(environment("IAM_TEST_DB_URL"));
            config.setUsername(environment("IAM_TEST_DB_USERNAME"));
            config.setPassword(environment("IAM_TEST_DB_PASSWORD"));
        } else {
            postgres = new PostgreSQLContainer<>("postgres:16.9-alpine")
                    .withDatabaseName("enterpriseiam_refresh_test")
                    .withUsername("iam_test").withPassword("test-only-password");
            postgres.start();
            config.setJdbcUrl(postgres.getJdbcUrl());
            config.setUsername(postgres.getUsername());
            config.setPassword(postgres.getPassword());
        }
        config.setMaximumPoolSize(6);
        config.setMinimumIdle(1);
        dataSource = new HikariDataSource(config);
        jdbc = new JdbcTemplate(dataSource);
        transactionManager = new JdbcTransactionManager(dataSource);
        Flyway.configure().dataSource(dataSource).defaultSchema("iam").schemas("iam")
                .locations("classpath:db/migration").load().migrate();
    }

    @BeforeEach
    void createServices() {
        clock = new MutableClock(Instant.parse("2026-10-23T10:00:00Z"));
        service = new RefreshTokenService(jdbc, clock, new TokenProperties(TTL), transactionManager);
        sessions = new SessionRegistry(jdbc, clock);
    }

    @AfterEach
    void removeFixtures() {
        users.forEach(user -> jdbc.update("DELETE FROM iam.users WHERE id = ?", user));
        users.clear();
    }

    @AfterAll
    void closeDatabase() {
        if (dataSource != null) {
            dataSource.close();
        }
        if (postgres != null) {
            postgres.stop();
        }
    }

    @Test
    void persistsOnlyHashAndBindsSessionAndTokenToTheSameActiveUser() {
        UUID user = insertUser("ACTIVE");
        IssuedRefreshToken issued = service.create(user);
        assertEquals(user, issued.userId());
        assertTrue(sessions.isActive(user, issued.sessionId()));
        assertFalse(sessions.isActive(UUID.randomUUID(), issued.sessionId()));
        assertEquals(clock.instant().plus(TTL), issued.expiresAt());
        String storedHash = jdbc.queryForObject(
                "SELECT token_hash FROM iam.refresh_tokens WHERE family_id = ?", String.class, issued.sessionId());
        assertEquals(new RefreshTokenCodec().hash(issued.rawToken()), storedHash);
        assertNotEquals(issued.rawToken(), storedHash);
        assertEquals(64, storedHash.length());

        UUID otherUser = insertUser("ACTIVE");
        assertThrows(DataIntegrityViolationException.class, () -> jdbc.update("""
                INSERT INTO iam.refresh_tokens (id, user_id, token_hash, family_id, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, UUID.randomUUID(), otherUser, "a".repeat(64), issued.sessionId(),
                Timestamp.from(clock.instant()), Timestamp.from(issued.expiresAt())));
    }

    @Test
    void rotationIsSingleUseAndDoesNotExtendAbsoluteSessionLifetime() {
        UUID user = insertUser("ACTIVE");
        IssuedRefreshToken original = service.create(user);
        clock.advance(Duration.ofDays(5));
        IssuedRefreshToken successor = service.rotate(original.rawToken());
        assertEquals(original.sessionId(), successor.sessionId());
        assertEquals(original.expiresAt(), successor.expiresAt());
        assertNotEquals(original.rawToken(), successor.rawToken());
        assertEquals(2, tokenCount(original.sessionId()));
        assertEquals(1, activeTokens(original.sessionId()));
        assertNotNull(jdbc.queryForObject("""
                SELECT replaced_by_token_id FROM iam.refresh_tokens WHERE token_hash = ?
                """, UUID.class, new RefreshTokenCodec().hash(original.rawToken())));
        assertTrue(sessions.isActive(user, original.sessionId()));
    }

    @Test
    void replayRevocationSurvivesItsAuthenticationExceptionAndAnOuterTransactionRollback() {
        UUID user = insertUser("ACTIVE");
        IssuedRefreshToken original = service.create(user);
        IssuedRefreshToken successor = service.rotate(original.rawToken());
        new TransactionTemplate(transactionManager).executeWithoutResult(transaction -> {
            assertThrows(BadCredentialsException.class, () -> service.rotate(original.rawToken()));
            transaction.setRollbackOnly();
        });
        assertFalse(sessions.isActive(user, original.sessionId()));
        assertEquals(0, activeTokens(original.sessionId()));
        assertThrows(BadCredentialsException.class, () -> service.rotate(successor.rawToken()));
        assertEquals(2, tokenCount(original.sessionId()), "Retain replay evidence until family retention expires");
    }

    @Test
    void simultaneousUseOfOneTokenAllowsOneRotationThenRevokesTheEntireFamily() throws Exception {
        UUID user = insertUser("ACTIVE");
        IssuedRefreshToken original = service.create(user);
        List<Attempt> outcomes = race(
                () -> attemptRotation(original.rawToken()), () -> attemptRotation(original.rawToken()));
        assertEquals(1, outcomes.stream().filter(result -> result.issued() != null).count());
        assertEquals(1, outcomes.stream().filter(result -> result.rejected()).count());
        assertFalse(sessions.isActive(user, original.sessionId()));
        assertEquals(0, activeTokens(original.sessionId()));
        IssuedRefreshToken returned = outcomes.stream().map(Attempt::issued)
                .filter(value -> value != null).findFirst().orElseThrow();
        assertThrows(BadCredentialsException.class, () -> service.rotate(returned.rawToken()));
    }

    @Test
    void racingOldTokenReplayWithSuccessorRotationCannotLeaveAnActiveDescendant() throws Exception {
        UUID user = insertUser("ACTIVE");
        IssuedRefreshToken original = service.create(user);
        IssuedRefreshToken successor = service.rotate(original.rawToken());
        List<Attempt> outcomes = race(
                () -> attemptRotation(original.rawToken()), () -> attemptRotation(successor.rawToken()));
        assertTrue(outcomes.getFirst().rejected());
        assertFalse(sessions.isActive(user, original.sessionId()));
        assertEquals(0, activeTokens(original.sessionId()));
        for (Attempt outcome : outcomes) {
            if (outcome.issued() != null) {
                assertThrows(BadCredentialsException.class, () -> service.rotate(outcome.issued().rawToken()));
            }
        }
    }

    @Test
    void logoutValidatesOwnershipAndIsIdempotentWithoutChangingTheRevocationTime() {
        UUID user = insertUser("ACTIVE");
        UUID otherUser = insertUser("ACTIVE");
        IssuedRefreshToken issued = service.create(user);
        assertThrows(BadCredentialsException.class, () -> service.revokeSession(otherUser, issued.sessionId()));
        assertTrue(sessions.isActive(user, issued.sessionId()));
        service.revokeSession(user, issued.sessionId());
        Instant revoked = jdbc.queryForObject("SELECT revoked_at FROM iam.auth_sessions WHERE id = ?",
                Timestamp.class, issued.sessionId()).toInstant();
        clock.advance(Duration.ofHours(1));
        service.revokeSession(user, issued.sessionId());
        assertEquals(revoked, jdbc.queryForObject("SELECT revoked_at FROM iam.auth_sessions WHERE id = ?",
                Timestamp.class, issued.sessionId()).toInstant());
        assertFalse(sessions.isActive(user, issued.sessionId()));
        assertEquals(0, activeTokens(issued.sessionId()));
    }

    @Test
    void logoutRacingRotationRevokesEveryPossibleSuccessor() throws Exception {
        UUID user = insertUser("ACTIVE");
        IssuedRefreshToken issued = service.create(user);
        race(() -> attemptRotation(issued.rawToken()), () -> {
            service.revokeSession(user, issued.sessionId());
            return new Attempt(null, false);
        });
        assertFalse(sessions.isActive(user, issued.sessionId()));
        assertEquals(0, activeTokens(issued.sessionId()));
    }

    @Test
    void expiryRejectsBothRefreshAndAccessAtTheExactDeadlineAndRetainsEvidence() {
        UUID user = insertUser("ACTIVE");
        IssuedRefreshToken issued = service.create(user);
        clock.advance(TTL);
        assertFalse(sessions.isActive(user, issued.sessionId()));
        assertThrows(BadCredentialsException.class, () -> service.rotate(issued.rawToken()));
        assertEquals(1, tokenCount(issued.sessionId()));
    }

    @Test
    void pendingLockedDisabledAndUnknownAccountsCannotCreateSessions() {
        for (String status : List.of("PENDING_VERIFICATION", "LOCKED", "DISABLED")) {
            UUID user = insertUser(status);
            assertThrows(BadCredentialsException.class, () -> service.create(user));
            assertEquals(0, jdbc.queryForObject(
                    "SELECT count(*) FROM iam.auth_sessions WHERE user_id = ?", Integer.class, user));
        }
        assertThrows(BadCredentialsException.class, () -> service.create(UUID.randomUUID()));
    }

    @Test
    void accountStatusChangesTakeEffectWithoutWaitingForCachedSessionExpiry() {
        UUID user = insertUser("ACTIVE");
        IssuedRefreshToken issued = service.create(user);
        assertTrue(sessions.isActive(user, issued.sessionId()));
        jdbc.update("UPDATE iam.users SET status = 'DISABLED' WHERE id = ?", user);
        assertFalse(sessions.isActive(user, issued.sessionId()));
        assertThrows(BadCredentialsException.class, () -> service.rotate(issued.rawToken()));
        assertEquals(1, tokenCount(issued.sessionId()));
    }

    @Test
    void wellFormedUnknownTokensAreRejectedWithoutCreatingState() {
        assertThrows(BadCredentialsException.class, () -> service.rotate(new RefreshTokenCodec().generate()));
    }

    @Test
    void migrationBackfillsExistingFamiliesWithoutExtendingTheirEarliestExpiration() {
        String schema = "iam_upgrade_" + UUID.randomUUID().toString().replace("-", "");
        try {
            migration(schema, "1").migrate();
            UUID user = insertLegacyUser(schema);
            UUID rotatedFamily = UUID.randomUUID();
            UUID revokedFamily = UUID.randomUUID();
            Instant created = clock.instant();
            insertLegacyToken(schema, user, rotatedFamily, created, created.plus(Duration.ofDays(10)), true);
            insertLegacyToken(schema, user, rotatedFamily, created.plus(Duration.ofDays(1)),
                    created.plus(Duration.ofDays(20)), false);
            insertLegacyToken(schema, user, revokedFamily, created, created.plus(Duration.ofDays(30)), true);
            migration(schema, "latest").migrate();

            assertEquals(created.plus(Duration.ofDays(10)), jdbc.queryForObject(
                    "SELECT expires_at FROM " + schema + ".auth_sessions WHERE id = ?",
                    Timestamp.class, rotatedFamily).toInstant());
            assertTrue(Boolean.TRUE.equals(jdbc.queryForObject(
                    "SELECT revoked_at IS NULL FROM " + schema + ".auth_sessions WHERE id = ?",
                    Boolean.class, rotatedFamily)));
            assertNotNull(jdbc.queryForObject(
                    "SELECT revoked_at FROM " + schema + ".auth_sessions WHERE id = ?",
                    Timestamp.class, revokedFamily));
            assertEquals(3, jdbc.queryForObject(
                    "SELECT count(*) FROM " + schema + ".refresh_tokens", Integer.class));
        } finally {
            jdbc.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
        }
    }

    @Test
    void migrationRejectsAmbiguousLegacyFamilyOwnershipTransactionally() {
        String schema = "iam_upgrade_" + UUID.randomUUID().toString().replace("-", "");
        try {
            migration(schema, "1").migrate();
            UUID first = insertLegacyUser(schema);
            UUID second = insertLegacyUser(schema);
            UUID family = UUID.randomUUID();
            Instant created = clock.instant();
            insertLegacyToken(schema, first, family, created, created.plus(TTL), false);
            insertLegacyToken(schema, second, family, created, created.plus(TTL), false);
            assertThrows(FlywayException.class, () -> migration(schema, "latest").migrate());
            assertEquals(2, jdbc.queryForObject(
                    "SELECT count(*) FROM " + schema + ".refresh_tokens", Integer.class));
            assertFalse(Boolean.TRUE.equals(jdbc.queryForObject("""
                    SELECT EXISTS (SELECT 1 FROM information_schema.tables
                    WHERE table_schema = ? AND table_name = 'auth_sessions')
                    """, Boolean.class, schema)), "Failed migration must not leave a partial session table");
        } finally {
            jdbc.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
        }
    }

    private Flyway migration(String schema, String target) {
        return Flyway.configure().dataSource(dataSource).defaultSchema(schema).schemas(schema)
                .target(target).locations("classpath:db/migration").load();
    }

    private UUID insertLegacyUser(String schema) {
        UUID user = UUID.randomUUID();
        jdbc.update("INSERT INTO " + schema + ".users (id, email, password_hash, department) "
                + "VALUES (?, ?, ?, 'Security')", user, user + "@example.test", PASSWORD);
        return user;
    }

    private void insertLegacyToken(String schema, UUID user, UUID family, Instant created,
                                   Instant expires, boolean revoked) {
        RefreshTokenCodec codec = new RefreshTokenCodec();
        jdbc.update("INSERT INTO " + schema + ".refresh_tokens "
                + "(id, user_id, token_hash, family_id, created_at, expires_at, revoked, revoked_at) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", UUID.randomUUID(), user, codec.hash(codec.generate()),
                family, Timestamp.from(created), Timestamp.from(expires), revoked,
                revoked ? Timestamp.from(created.plusSeconds(1)) : null);
    }

    private UUID insertUser(String status) {
        UUID user = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO iam.users (id, email, password_hash, status, department, clearance_level)
                VALUES (?, ?, ?, ?, 'Security', 2)
                """, user, user + "@example.test", PASSWORD, status);
        users.add(user);
        return user;
    }

    private int tokenCount(UUID session) {
        return jdbc.queryForObject(
                "SELECT count(*) FROM iam.refresh_tokens WHERE family_id = ?", Integer.class, session);
    }

    private int activeTokens(UUID session) {
        return jdbc.queryForObject(
                "SELECT count(*) FROM iam.refresh_tokens WHERE family_id = ? AND NOT revoked", Integer.class, session);
    }

    private Attempt attemptRotation(String rawToken) {
        try {
            return new Attempt(service.rotate(rawToken), false);
        } catch (BadCredentialsException expected) {
            return new Attempt(null, true);
        }
    }

    private List<Attempt> race(Callable<Attempt> first, Callable<Attempt> second) throws Exception {
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var one = executor.submit(() -> {
                ready.countDown();
                assertTrue(start.await(10, TimeUnit.SECONDS));
                return first.call();
            });
            var two = executor.submit(() -> {
                ready.countDown();
                assertTrue(start.await(10, TimeUnit.SECONDS));
                return second.call();
            });
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            start.countDown();
            return List.of(one.get(15, TimeUnit.SECONDS), two.get(15, TimeUnit.SECONDS));
        }
    }

    private static String environment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for a disposable test database");
        }
        return value;
    }

    private record Attempt(IssuedRefreshToken issued, boolean rejected) { }

    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> instant;

        private MutableClock(Instant instant) {
            this.instant = new AtomicReference<>(instant);
        }

        void advance(Duration duration) {
            instant.updateAndGet(value -> value.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new UnsupportedOperationException("Test clock is UTC only");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return instant.get();
        }
    }
}
