package com.enterpriseiam.security.tokens;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Service;

/** Reads committed session and account state on every authentication decision. */
@Service
public class SessionRegistry {

    private final JdbcTemplate jdbc;
    private final Clock clock;

    public SessionRegistry(JdbcTemplate jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    public boolean isActive(UUID userId, UUID sessionId) {
        if (userId == null || sessionId == null) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(jdbc.queryForObject("""
                    SELECT EXISTS (
                        SELECT 1 FROM iam.auth_sessions s
                        JOIN iam.users u ON u.id = s.user_id
                        WHERE s.id = ? AND s.user_id = ? AND s.revoked_at IS NULL
                            AND s.expires_at > ? AND u.status = 'ACTIVE'
                    )
                    """, Boolean.class, sessionId, userId, Timestamp.from(clock.instant())));
        } catch (DataAccessException exception) {
            // No positive cache or fail-open fallback: logout/replay revocation
            // must take effect immediately on the next authentication decision.
            throw new AuthenticationServiceException("Authentication state is unavailable", exception);
        }
    }
}
