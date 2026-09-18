package com.enterpriseiam.audit.persistence;

import com.enterpriseiam.audit.model.AuditEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.HexFormat;
import java.util.Objects;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Component
public class AuditRecorder {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final ApplicationEventPublisher publisher;
    private final TransactionTemplate independent;
    private final TransactionTemplate current;

    public AuditRecorder(JdbcTemplate jdbc, ObjectMapper mapper, ApplicationEventPublisher publisher,
            PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.mapper = mapper.copy().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.publisher = publisher;
        this.independent = new TransactionTemplate(transactionManager);
        this.independent.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.independent.setTimeout(3);
        this.current = new TransactionTemplate(transactionManager);
        this.current.setPropagationBehavior(TransactionDefinition.PROPAGATION_MANDATORY);
    }

    public void appendIndependent(AuditEvent event) {
        append(independent, event);
    }

    /** Uses the application's transaction manager, so a business rollback removes its success event. */
    public void appendInCurrentTransaction(AuditEvent event) {
        append(current, event);
    }

    private void append(TransactionTemplate transaction, AuditEvent event) {
        try {
            Objects.requireNonNull(event, "event");
            String payload = mapper.writeValueAsString(event);
            String digest = sha256(payload);
            transaction.executeWithoutResult(status -> {
                int inserted = jdbc.update("""
                        INSERT INTO iam.audit_events (id, occurred_at, payload, payload_sha256)
                        VALUES (?, ?, CAST(? AS jsonb), ?) ON CONFLICT (id) DO NOTHING
                        """, event.id(), Timestamp.from(event.occurredAt()), payload, digest);
                if (inserted == 0) {
                    Boolean identical = jdbc.queryForObject("""
                            SELECT payload_sha256 = ? AND payload = CAST(? AS jsonb)
                            FROM iam.audit_events WHERE id = ?
                            """, Boolean.class, digest, payload, event.id());
                    if (!Boolean.TRUE.equals(identical)) {
                        throw new IllegalStateException("Audit event identity collision");
                    }
                }
                jdbc.update("INSERT INTO iam.audit_delivery(event_id) VALUES (?) ON CONFLICT DO NOTHING", event.id());
                publisher.publishEvent(new AuditPendingEvent());
            });
        } catch (RuntimeException | JsonProcessingException failure) {
            throw new AuditUnavailableException(failure);
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
