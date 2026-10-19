package com.enterpriseiam.audit.delivery;

import com.enterpriseiam.audit.config.AuditProperties;
import com.enterpriseiam.audit.model.AuditEvent;
import com.enterpriseiam.audit.model.AuditPhase;
import com.enterpriseiam.audit.persistence.AuditDeliveryStore;
import com.enterpriseiam.audit.persistence.AuditDeliveryStore.Claim;
import com.enterpriseiam.audit.persistence.AuditPendingEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.TaskRejectedException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AuditDispatcherTest {
    private final AuditDeliveryStore store = mock(AuditDeliveryStore.class);
    private final AuditDocumentRepository documents = mock(AuditDocumentRepository.class);
    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();
    private final AuditProperties properties = new AuditProperties(null, null, null, null, null, null, null, null, null);
    private final AuditDispatcher dispatcher = new AuditDispatcher(store, documents, mapper, properties, metrics);

    @Test
    void commitsDeliveryOnlyAfterTheCreateRequestSucceeds() throws Exception {
        Claim claim = claim(1);
        arrange(claim);
        when(documents.createOnly(any())).thenReturn(AuditDocumentRepository.CreateResult.CREATED);
        when(store.complete(claim)).thenReturn(true);
        dispatcher.dispatchBatch();
        var order = inOrder(store, documents);
        order.verify(store).claimBatch(properties.batchSize(), properties.leaseDuration());
        order.verify(store).renew(claim, properties.leaseDuration());
        order.verify(documents).createOnly(any());
        order.verify(store).complete(claim);
        verify(store, never()).retry(any(), any(), any());
        assertEquals(1, metrics.get("iam.audit.delivery.completed").counter().count());
    }

    @Test
    void uncertainElasticsearchFailureRetainsAndRetriesEventEvenBeyondAlertThreshold() throws Exception {
        Claim claim = claim(100);
        arrange(claim);
        when(documents.createOnly(any())).thenThrow(new IllegalStateException("sensitive remote body"));
        dispatcher.dispatchBatch();
        verify(store).retry(claim, Duration.ofHours(1), "DELIVERY_FAILED");
        verify(store, never()).complete(any());
        assertEquals(1, metrics.get("iam.audit.delivery.overdue").counter().count());
    }

    @Test
    void lostLeasePreventsSendingAnAlreadyReclaimedEvent() throws Exception {
        Claim claim = claim(1);
        when(store.claimBatch(anyInt(), any())).thenReturn(List.of(claim));
        dispatcher.dispatchBatch();
        verifyNoInteractions(documents);
        verify(store, never()).complete(any());
    }

    @Test
    void corruptedPayloadRetriesWithoutSendingOrDroppingIt() {
        Claim claim = new Claim(UUID.randomUUID(), UUID.randomUUID(), 1, "{}");
        arrange(claim);
        dispatcher.dispatchBatch();
        verifyNoInteractions(documents);
        verify(store).retry(claim, Duration.ofSeconds(5), "DELIVERY_FAILED");
    }

    @Test
    void databaseOutageIsContainedForFutureScheduledRecovery() {
        when(store.claimBatch(anyInt(), any())).thenThrow(new IllegalStateException("database unavailable"));
        assertDoesNotThrow(dispatcher::dispatchBatch);
        assertEquals(1, metrics.get("iam.audit.dispatch.errors").counter().count());
    }

    @Test
    void exponentialBackoffIsBoundedWithoutAnAttemptLimitOrOverflow() {
        assertEquals(Duration.ofSeconds(5), dispatcher.retryDelay(1));
        assertEquals(Duration.ofSeconds(10), dispatcher.retryDelay(2));
        assertEquals(Duration.ofHours(1), dispatcher.retryDelay(Long.MAX_VALUE));
    }

    @Test
    void disablingDeliveryStillAllowsCaptureAndDoesNotReadTheOutbox() {
        AuditProperties disabled = new AuditProperties(false, null, null, null, null, null, null, null, null);
        new AuditDispatcher(store, documents, mapper, disabled, metrics).dispatchBatch();
        verifyNoInteractions(store, documents);
    }

    @Test
    void saturationCannotFailTheAfterCommitCallbackAndTheSweepCanRetryLater() {
        AuditDispatcher asynchronous = mock(AuditDispatcher.class);
        doThrow(new TaskRejectedException("full")).doNothing().when(asynchronous).dispatchBatch();
        AuditDispatchTrigger trigger = new AuditDispatchTrigger(asynchronous, metrics);
        assertDoesNotThrow(() -> trigger.committed(new AuditPendingEvent()));
        trigger.recoverPending();
        verify(asynchronous, times(2)).dispatchBatch();
        assertEquals(1, metrics.get("iam.audit.dispatch.rejected").counter().count());
    }

    private void arrange(Claim claim) {
        when(store.claimBatch(anyInt(), any())).thenReturn(List.of(claim));
        when(store.renew(eq(claim), any())).thenReturn(true);
    }

    private Claim claim(long attempts) throws Exception {
        AuditEvent event = new AuditEvent(UUID.randomUUID(), UUID.randomUUID(), Instant.now(), "RESOURCE_READ",
                AuditPhase.SUCCEEDED, "anonymous", "ResourceService.read", Map.of(), "127.0.0.1",
                "test", "GET", "/api/v1/resources/{id}", "SUCCESS");
        return new Claim(event.id(), UUID.randomUUID(), attempts, mapper.writeValueAsString(event));
    }
}
