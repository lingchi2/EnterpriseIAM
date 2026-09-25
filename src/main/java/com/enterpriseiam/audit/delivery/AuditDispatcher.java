package com.enterpriseiam.audit.delivery;

import com.enterpriseiam.audit.config.AuditProperties;
import com.enterpriseiam.audit.model.AuditEvent;
import com.enterpriseiam.audit.persistence.AuditDeliveryStore;
import com.enterpriseiam.audit.persistence.AuditDeliveryStore.Claim;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
public class AuditDispatcher {
    private static final Logger LOG = LoggerFactory.getLogger(AuditDispatcher.class);
    private final AuditDeliveryStore store;
    private final AuditDocumentRepository documents;
    private final ObjectMapper mapper;
    private final AuditProperties properties;
    private final MeterRegistry metrics;

    public AuditDispatcher(AuditDeliveryStore store, AuditDocumentRepository documents,
            ObjectMapper mapper, AuditProperties properties, MeterRegistry metrics) {
        this.store = store;
        this.documents = documents;
        this.mapper = mapper;
        this.properties = properties;
        this.metrics = metrics;
    }

    @Async("auditExecutor")
    public void dispatchBatch() {
        if (!properties.dispatcherEnabled()) {
            return;
        }
        try {
            List<Claim> claims = store.claimBatch(properties.batchSize(), properties.leaseDuration());
            for (Claim claim : claims) {
                deliver(claim);
            }
        } catch (RuntimeException failure) {
            metrics.counter("iam.audit.dispatch.errors").increment();
            // Never log exception messages: Elasticsearch error bodies may repeat audit fields.
            LOG.warn("Audit delivery polling failed; durable events remain pending");
        }
    }

    private void deliver(Claim claim) {
        if (!store.renew(claim, properties.leaseDuration())) {
            return;
        }
        try {
            AuditEvent event = mapper.readValue(claim.payload(), AuditEvent.class);
            if (!claim.eventId().equals(event.id())) {
                throw new IllegalStateException("Audit payload identity mismatch");
            }
            AuditDocumentRepository.CreateResult result = documents.createOnly(AuditDocument.from(event));
            if (store.complete(claim)) {
                metrics.counter("iam.audit.delivery.completed", "result", result.name()).increment();
            }
        } catch (Exception failure) {
            store.retry(claim, retryDelay(claim.attempts()), "DELIVERY_FAILED");
            metrics.counter("iam.audit.delivery.retries").increment();
            if (claim.attempts() >= properties.retryAlertThreshold()) {
                metrics.counter("iam.audit.delivery.overdue").increment();
                LOG.error("Audit delivery exceeded retry alert threshold; retained for continued retry");
            }
        }
    }

    Duration retryDelay(long attempts) {
        int exponent = (int) Math.min(Math.max(attempts - 1, 0), 30);
        long multiplier = 1L << exponent;
        long base = properties.retryBaseDelay().toMillis();
        long maximum = properties.retryMaxDelay().toMillis();
        return Duration.ofMillis(Math.min(maximum, base * multiplier));
    }
}
