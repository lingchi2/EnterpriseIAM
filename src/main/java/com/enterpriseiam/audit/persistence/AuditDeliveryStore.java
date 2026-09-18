package com.enterpriseiam.audit.persistence;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** All leases use PostgreSQL time, avoiding clock skew between service replicas. */
@Component
public class AuditDeliveryStore {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;

    public AuditDeliveryStore(JdbcTemplate jdbc, PlatformTransactionManager manager) {
        this.jdbc = jdbc;
        this.transaction = new TransactionTemplate(manager);
        this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.transaction.setTimeout(3);
    }

    public List<Claim> claimBatch(int limit, Duration leaseDuration) {
        UUID leaseToken = UUID.randomUUID();
        return transaction.execute(status -> jdbc.query("""
                WITH candidates AS (
                    SELECT event_id FROM iam.audit_delivery
                    WHERE delivered_at IS NULL AND next_attempt_at <= CURRENT_TIMESTAMP
                        AND (lease_until IS NULL OR lease_until <= CURRENT_TIMESTAMP)
                    ORDER BY next_attempt_at, event_id
                    FOR UPDATE SKIP LOCKED LIMIT ?
                ), claimed AS (
                    UPDATE iam.audit_delivery d
                    SET lease_token = ?, lease_until = clock_timestamp() + ? * INTERVAL '1 millisecond',
                        attempts = LEAST(d.attempts, 9223372036854775806) + 1
                    FROM candidates c WHERE d.event_id = c.event_id
                    RETURNING d.event_id, d.lease_token, d.attempts
                )
                SELECT c.event_id, c.lease_token, c.attempts, e.payload::text
                FROM claimed c JOIN iam.audit_events e ON e.id = c.event_id
                """, (result, row) -> new Claim(result.getObject("event_id", UUID.class),
                        result.getObject("lease_token", UUID.class), result.getLong("attempts"),
                        result.getString("payload")), limit, leaseToken, leaseDuration.toMillis()));
    }

    /** Recheck ownership immediately before sending each item from a claimed batch. */
    public boolean renew(Claim claim, Duration leaseDuration) {
        return Boolean.TRUE.equals(transaction.execute(status -> jdbc.update("""
                UPDATE iam.audit_delivery SET lease_until = clock_timestamp() + ? * INTERVAL '1 millisecond'
                WHERE event_id = ? AND lease_token = ? AND delivered_at IS NULL
                    AND lease_until > clock_timestamp()
                """, leaseDuration.toMillis(), claim.eventId(), claim.leaseToken()) == 1));
    }

    public boolean complete(Claim claim) {
        return Boolean.TRUE.equals(transaction.execute(status -> jdbc.update("""
                UPDATE iam.audit_delivery SET delivered_at = clock_timestamp(), lease_until = NULL,
                    lease_token = NULL, last_error_code = NULL
                WHERE event_id = ? AND lease_token = ? AND delivered_at IS NULL
                """, claim.eventId(), claim.leaseToken()) == 1));
    }

    public boolean retry(Claim claim, Duration delay, String errorCode) {
        return Boolean.TRUE.equals(transaction.execute(status -> jdbc.update("""
                UPDATE iam.audit_delivery
                SET next_attempt_at = clock_timestamp() + ? * INTERVAL '1 millisecond',
                    lease_until = NULL, lease_token = NULL, last_error_code = ?
                WHERE event_id = ? AND lease_token = ? AND delivered_at IS NULL
                """, delay.toMillis(), errorCode, claim.eventId(), claim.leaseToken()) == 1));
    }

    public record Claim(UUID eventId, UUID leaseToken, long attempts, String payload) {
        @Override
        public String toString() {
            return "AuditClaim[eventId=" + eventId + ", attempts=" + attempts + "]";
        }
    }
}
