package com.enterpriseiam.security.tokens;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Atomic one-time refresh rotation with durable family revocation on replay.
 * Authentication transactions are independent of caller business transactions.
 * Callers must not retry refresh requests: a repeated token revokes the family.
 */
@Service
public class RefreshTokenService {

    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final TokenProperties properties;
    private final TransactionTemplate transactions;
    private final RefreshTokenCodec codec = new RefreshTokenCodec();

    public RefreshTokenService(JdbcTemplate jdbc, Clock clock, TokenProperties properties,
                               PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.clock = clock;
        this.properties = properties;
        this.transactions = new TransactionTemplate(transactionManager);
        this.transactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.transactions.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        this.transactions.setTimeout(5);
    }

    public IssuedRefreshToken create(UUID userId) {
        if (userId == null) {
            throw RefreshTokenCodec.invalidToken();
        }
        return databaseOperation(() -> transactions.execute(status -> {
            if (!lockActiveUser(userId)) {
                throw RefreshTokenCodec.invalidToken();
            }
            Instant now = now();
            Instant expiresAt = now.plus(properties.refreshTokenTtl()).truncatedTo(ChronoUnit.MICROS);
            UUID sessionId = UUID.randomUUID();
            jdbc.update("""
                    INSERT INTO iam.auth_sessions (id, user_id, created_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    """, sessionId, userId, Timestamp.from(now), Timestamp.from(expiresAt));
            return insertToken(userId, sessionId, now, expiresAt).issued();
        }));
    }

    public IssuedRefreshToken rotate(String rawToken) {
        String tokenHash = codec.hash(rawToken);
        IssuedRefreshToken result = databaseOperation(() -> transactions.execute(status -> {
            List<UUID> families = jdbc.query("""
                    SELECT family_id FROM iam.refresh_tokens WHERE token_hash = ?
                    """, (rs, row) -> rs.getObject("family_id", UUID.class), tokenHash);
            if (families.isEmpty()) {
                return null;
            }
            Session session = lockSession(families.getFirst());
            Instant now = now();
            if (session == null || session.revokedAt() != null || !session.expiresAt().isAfter(now)) {
                return null;
            }
            // This family lock is acquired before token state is read or changed
            // by any rotation/revocation. Concurrent successor rotation and old
            // token replay therefore cannot leave a surviving active successor.
            List<StoredToken> tokens = jdbc.query("""
                    SELECT id, user_id, expires_at, revoked FROM iam.refresh_tokens
                    WHERE token_hash = ? AND family_id = ?
                    """, (rs, row) -> new StoredToken(rs.getObject("id", UUID.class),
                            rs.getObject("user_id", UUID.class),
                            rs.getTimestamp("expires_at").toInstant(), rs.getBoolean("revoked")),
                    tokenHash, session.id());
            if (tokens.isEmpty()) {
                return null;
            }
            StoredToken token = tokens.getFirst();
            if (token.revoked()) {
                revokeFamily(session.id(), now);
                return null;
            }
            if (!token.expiresAt().isAfter(now) || !lockActiveUser(session.userId())) {
                return null;
            }
            InsertedToken successor = insertToken(session.userId(), session.id(), now, session.expiresAt());
            jdbc.update("""
                    UPDATE iam.refresh_tokens
                    SET revoked = true, revoked_at = greatest(created_at, ?),
                        replaced_by_token_id = ?, version = version + 1
                    WHERE id = ?
                    """, Timestamp.from(now), successor.id(), token.id());
            return successor.issued();
        }));
        // Throw only after committing replay revocation. Throwing from the
        // transaction callback would roll back the security response itself.
        if (result == null) {
            throw RefreshTokenCodec.invalidToken();
        }
        return result;
    }

    public void revokeSession(UUID userId, UUID sessionId) {
        if (userId == null || sessionId == null) {
            throw RefreshTokenCodec.invalidToken();
        }
        databaseOperation(() -> transactions.execute(status -> {
            Session session = lockSession(sessionId);
            if (session == null || !session.userId().equals(userId)) {
                throw RefreshTokenCodec.invalidToken();
            }
            revokeFamily(sessionId, now());
            return null;
        }));
    }

    private boolean lockActiveUser(UUID userId) {
        return !jdbc.query("""
                SELECT id FROM iam.users WHERE id = ? AND status = 'ACTIVE' FOR SHARE
                """, (rs, row) -> rs.getObject("id", UUID.class), userId).isEmpty();
    }

    private Session lockSession(UUID sessionId) {
        List<Session> sessions = jdbc.query("""
                SELECT id, user_id, expires_at, revoked_at FROM iam.auth_sessions
                WHERE id = ? FOR UPDATE
                """, (rs, row) -> {
                    Timestamp revokedAt = rs.getTimestamp("revoked_at");
                    return new Session(rs.getObject("id", UUID.class), rs.getObject("user_id", UUID.class),
                            rs.getTimestamp("expires_at").toInstant(),
                            revokedAt == null ? null : revokedAt.toInstant());
                }, sessionId);
        return sessions.isEmpty() ? null : sessions.getFirst();
    }

    private InsertedToken insertToken(UUID userId, UUID sessionId, Instant now, Instant expiresAt) {
        UUID tokenId = UUID.randomUUID();
        String rawToken = codec.generate();
        jdbc.update("""
                INSERT INTO iam.refresh_tokens
                    (id, user_id, token_hash, family_id, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, tokenId, userId, codec.hash(rawToken), sessionId,
                Timestamp.from(now), Timestamp.from(expiresAt));
        return new InsertedToken(tokenId, new IssuedRefreshToken(rawToken, userId, sessionId, expiresAt));
    }

    private void revokeFamily(UUID sessionId, Instant now) {
        jdbc.update("""
                UPDATE iam.auth_sessions SET revoked_at = greatest(created_at, ?)
                WHERE id = ? AND revoked_at IS NULL
                """, Timestamp.from(now), sessionId);
        jdbc.update("""
                UPDATE iam.refresh_tokens
                SET revoked = true, revoked_at = greatest(created_at, ?), version = version + 1
                WHERE family_id = ? AND NOT revoked
                """, Timestamp.from(now), sessionId);
    }

    private Instant now() {
        return clock.instant().truncatedTo(ChronoUnit.MICROS);
    }

    private <T> T databaseOperation(Supplier<T> operation) {
        try {
            return operation.get();
        } catch (DataAccessException | TransactionException exception) {
            throw new AuthenticationServiceException("Authentication state is unavailable", exception);
        }
    }

    private record Session(UUID id, UUID userId, Instant expiresAt, Instant revokedAt) { }

    private record StoredToken(UUID id, UUID userId, Instant expiresAt, boolean revoked) { }

    private record InsertedToken(UUID id, IssuedRefreshToken issued) { }
}
