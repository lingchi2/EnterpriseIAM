package com.enterpriseiam.audit.delivery;

import com.enterpriseiam.audit.persistence.AuditPendingEvent;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class AuditDispatchTrigger {
    private final AuditDispatcher dispatcher;
    private final MeterRegistry metrics;

    public AuditDispatchTrigger(AuditDispatcher dispatcher, MeterRegistry metrics) {
        this.dispatcher = dispatcher;
        this.metrics = metrics;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void committed(AuditPendingEvent ignored) {
        wake();
    }

    @Scheduled(fixedDelayString = "#{@'iam.audit-com.enterpriseiam.audit.config.AuditProperties'.pollInterval().toMillis()}")
    public void recoverPending() {
        wake();
    }

    private void wake() {
        try {
            dispatcher.dispatchBatch();
        } catch (TaskRejectedException saturated) {
            // This is an optimization only: a periodic sweep recovers missed notifications.
            // In particular, executor saturation must never fail an already committed request.
            metrics.counter("iam.audit.dispatch.rejected").increment();
        }
    }
}
