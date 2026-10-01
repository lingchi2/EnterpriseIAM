package com.enterpriseiam.audit.capture;

import com.enterpriseiam.audit.annotation.AuditAction;
import com.enterpriseiam.audit.model.AuditEvent;
import com.enterpriseiam.audit.model.AuditPhase;
import com.enterpriseiam.audit.persistence.AuditRecorder;
import com.enterpriseiam.audit.persistence.AuditUnavailableException;
import java.time.Clock;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Transaction advice (order 0) wraps this aspect, which wraps method authorization (order 200).
 * A durable STARTED event gates execution. Transactional success commits with the business write;
 * denial, exceptions and transaction rollbacks produce an independent FAILED event.
 */
@Aspect
@Component
@Order(50)
public class AuditAspect {
    private static final Logger LOG = LoggerFactory.getLogger(AuditAspect.class);
    private final AuditRecorder recorder;
    private final Clock clock;

    public AuditAspect(AuditRecorder recorder, Clock clock) {
        this.recorder = recorder;
        this.clock = clock;
    }

    @Around("@annotation(action)")
    public Object audit(ProceedingJoinPoint invocation, AuditAction action) throws Throwable {
        MethodSignature signature = (MethodSignature) invocation.getSignature();
        AuditSnapshot snapshot = AuditSnapshot.capture(action.action(), signature.getMethod(), invocation.getArgs());
        UUID terminalId = UUID.randomUUID();
        appendIndependent(snapshot.event(UUID.randomUUID(), clock.instant(), AuditPhase.STARTED, "PENDING"));
        AtomicReference<AuditEvent> completionFailure = new AtomicReference<>();
        boolean transactionalTerminalAttempted = false;
        try {
            Object result = invocation.proceed();
            AuditEvent success = snapshot.event(terminalId, clock.instant(), AuditPhase.SUCCEEDED,
                    signature.getReturnType() == void.class ? "VOID" : result == null ? "NULL" : "RETURNED");
            if (TransactionSynchronizationManager.isActualTransactionActive()) {
                if (!TransactionSynchronizationManager.isSynchronizationActive()) {
                    throw new AuditUnavailableException("Audit transaction synchronization unavailable");
                }
                registerCompletion(snapshot, terminalId, completionFailure);
                transactionalTerminalAttempted = true;
                appendInCurrentTransaction(success);
            } else {
                appendIndependent(success);
            }
            return result;
        } catch (Throwable businessFailure) {
            AuditEvent failed = snapshot.event(terminalId, clock.instant(), AuditPhase.FAILED,
                    failureType(businessFailure));
            if (transactionalTerminalAttempted) {
                // A partial append can still hold this event's unique key until rollback. Inserting
                // the same ID in REQUIRES_NEW here would wait on our own suspended transaction.
                // The outer transaction sees this exception; completion writes after locks release.
                completionFailure.set(failed);
                throw businessFailure;
            }
            try {
                appendIndependent(failed);
            } catch (RuntimeException auditFailure) {
                // Infrastructure failure takes precedence, while the original error stays available
                // to trusted diagnostic code. Neither exception message enters the audit document.
                auditFailure.addSuppressed(businessFailure);
                throw auditFailure;
            }
            throw businessFailure;
        }
    }

    private void registerCompletion(AuditSnapshot snapshot, UUID terminalId,
            AtomicReference<AuditEvent> completionFailure) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                if (status == STATUS_COMMITTED) {
                    return;
                }
                try {
                    AuditEvent failed = completionFailure.get();
                    appendIndependent(failed != null ? failed
                            : snapshot.event(terminalId, clock.instant(), AuditPhase.FAILED,
                                    status == STATUS_ROLLED_BACK
                                            ? "TRANSACTION_ROLLED_BACK" : "TRANSACTION_OUTCOME_UNKNOWN"));
                } catch (RuntimeException unavailable) {
                    // afterCompletion cannot change an already completed transaction. The durable
                    // STARTED record remains reconcilable; emit identifiers only, never throwables.
                    LOG.error("Audit terminal append unavailable; invocationId={} eventId={}",
                            snapshot.invocationId(), terminalId);
                }
            }
        });
    }

    private void appendIndependent(AuditEvent event) {
        try {
            recorder.appendIndependent(event);
        } catch (RuntimeException failure) {
            throw new AuditUnavailableException("Audit persistence unavailable", failure);
        }
    }

    private void appendInCurrentTransaction(AuditEvent event) {
        try {
            recorder.appendInCurrentTransaction(event);
        } catch (RuntimeException failure) {
            throw new AuditUnavailableException("Audit persistence unavailable", failure);
        }
    }

    private static String failureType(Throwable failure) {
        if (failure instanceof AuditUnavailableException) return "AUDIT_UNAVAILABLE";
        if (failure instanceof AccessDeniedException) return "ACCESS_DENIED";
        if (failure instanceof AuthenticationException) return "AUTHENTICATION_FAILED";
        if (failure instanceof IllegalArgumentException) return "VALIDATION_FAILED";
        return "INTERNAL_ERROR";
    }
}
