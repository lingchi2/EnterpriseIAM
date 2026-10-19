package com.enterpriseiam.audit.capture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verifyNoInteractions;

import com.enterpriseiam.audit.annotation.AuditAction;
import com.enterpriseiam.audit.model.AuditEvent;
import com.enterpriseiam.audit.model.AuditPhase;
import com.enterpriseiam.audit.persistence.AuditRecorder;
import com.enterpriseiam.audit.persistence.AuditUnavailableException;
import com.enterpriseiam.security.identity.IamPrincipal;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@SpringJUnitConfig(AuditAspectTest.Config.class)
class AuditAspectTest {
    private static final Instant NOW = Instant.parse("2026-10-23T12:00:00Z");
    private static final UUID USER_ID = UUID.randomUUID();
    @Autowired AuditedService service;
    @Autowired AuditRecorder recorder;
    @Autowired TestTransactionManager transactions;
    private final List<AuditEvent> independent = new ArrayList<>();
    private final List<AuditEvent> committed = new ArrayList<>();
    private final List<AuditEvent> transactional = new ArrayList<>();

    @BeforeEach
    void setUp() {
        reset(recorder);
        transactions.failCommit = false;
        service.resetCount();
        authenticate();
        doAnswer(invocation -> {
            independent.add(invocation.getArgument(0));
            return null;
        }).when(recorder).appendIndependent(any());
        doAnswer(invocation -> {
            AuditEvent event = invocation.getArgument(0);
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            transactional.add(event);
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override public void afterCompletion(int status) {
                    if (status == STATUS_COMMITTED) committed.add(event);
                }
            });
            return null;
        }).when(recorder).appendInCurrentTransaction(any());
    }

    @AfterEach
    void clearContexts() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
    }

    @Test
    void actualAspectProxyProducesIndependentImmutableStartAndSuccess() {
        assertThat(AopUtils.isAopProxy(service)).isTrue();
        Object result = service.perform("secret-password", Map.of("nested-token", "bearer"));
        assertThat(result).isSameAs(AuditedService.OPAQUE_RESULT);
        assertThat(independent).extracting(AuditEvent::phase)
                .containsExactly(AuditPhase.STARTED, AuditPhase.SUCCEEDED);
        assertThat(independent).extracting(AuditEvent::invocationId).containsOnly(independent.getFirst().invocationId());
        assertThat(independent.getFirst().id()).isNotEqualTo(independent.getLast().id());
        assertThat(independent.getFirst().actorId()).isEqualTo(USER_ID.toString());
        assertThat(independent.getLast().outcomeType()).isEqualTo("RETURNED");
        assertThat(independent.getLast().occurredAt()).isEqualTo(NOW);
        assertThat(independent.getLast().arguments()).containsOnly(
                Map.entry("arg0", "[REDACTED]"), Map.entry("arg1", "[REDACTED]"));
        assertThat(transactional).isEmpty();
    }

    @Test
    void failedDurableStartPreventsTheBusinessMethod() {
        doThrow(new IllegalStateException("credentials=unsafe"))
                .when(recorder).appendIndependent(any());
        assertThatThrownBy(() -> service.perform("password", null))
                .isInstanceOf(AuditUnavailableException.class)
                .hasMessage("Audit persistence unavailable");
        assertThat(service.count()).isZero();
    }

    @Test
    void businessFailureIsRethrownWithoutLeakingExceptionDetailsToTheEvent() {
        IllegalStateException original = new IllegalStateException("password=secret");
        assertThatThrownBy(() -> service.fail(original)).isSameAs(original);
        assertThat(independent).extracting(AuditEvent::phase)
                .containsExactly(AuditPhase.STARTED, AuditPhase.FAILED);
        assertThat(independent.getLast().outcomeType()).isEqualTo("INTERNAL_ERROR");
        assertThat(independent.getLast().arguments()).containsEntry("arg0", "[REDACTED]");
        assertThat(independent.getLast().toString()).doesNotContain("secret", "password", USER_ID.toString());
    }

    @Test
    void auditFailureOverridesBusinessFailureWithSafeMessageAndPreservesOriginalAsSuppressed() {
        IllegalStateException original = new IllegalStateException("private-business-error");
        doAnswer(invocation -> {
            AuditEvent event = invocation.getArgument(0);
            if (event.phase() == AuditPhase.FAILED) throw new IllegalStateException("private-database-error");
            independent.add(event);
            return null;
        }).when(recorder).appendIndependent(any());
        assertThatThrownBy(() -> service.fail(original)).isInstanceOf(AuditUnavailableException.class)
                .hasMessage("Audit persistence unavailable")
                .satisfies(failure -> assertThat(failure.getSuppressed()).containsExactly(original));
        assertThat(independent).extracting(AuditEvent::phase).containsExactly(AuditPhase.STARTED);
    }

    @Test
    void actualMethodSecurityDenialIsCapturedBeforeTheBusinessMethodExecutes() {
        assertThatThrownBy(service::denied).isInstanceOf(AccessDeniedException.class);
        assertThat(service.count()).isZero();
        assertThat(independent).extracting(AuditEvent::phase)
                .containsExactly(AuditPhase.STARTED, AuditPhase.FAILED);
        assertThat(independent.getLast().outcomeType()).isEqualTo("ACCESS_DENIED");
    }

    @Test
    void transactionAdviceWrapsAuditAndSuccessCommitsWithBusinessTransaction() {
        service.transactionalSuccess();
        assertThat(independent).extracting(AuditEvent::phase).containsExactly(AuditPhase.STARTED);
        assertThat(committed).extracting(AuditEvent::phase).containsExactly(AuditPhase.SUCCEEDED);
        assertThat(committed.getFirst().outcomeType()).isEqualTo("VOID");
        assertThat(service.count()).isOne();
    }

    @Test
    void enclosingRollbackProducesFailedOutcomeInsteadOfCommittedSuccess() {
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            service.transactionalSuccess();
            assertThat(independent).hasSize(1);
            assertThat(committed).isEmpty();
            status.setRollbackOnly();
        });
        assertThat(independent).extracting(AuditEvent::phase)
                .containsExactly(AuditPhase.STARTED, AuditPhase.FAILED);
        assertThat(independent.getLast().outcomeType()).isEqualTo("TRANSACTION_ROLLED_BACK");
        assertThat(independent.getLast().id()).isEqualTo(transactional.getFirst().id());
        assertThat(committed).isEmpty();
    }

    @Test
    void uncertainCommitProducesExplicitUnknownOutcomeAndRetainsStartedEvent() {
        transactions.failCommit = true;
        assertThatThrownBy(service::transactionalSuccess).isInstanceOf(TransactionSystemException.class);
        assertThat(independent).extracting(AuditEvent::phase)
                .containsExactly(AuditPhase.STARTED, AuditPhase.FAILED);
        assertThat(independent.getLast().outcomeType()).isEqualTo("TRANSACTION_OUTCOME_UNKNOWN");
        assertThat(committed).isEmpty();
    }

    @Test
    void transactionalAppendFailureRollsBackAndRecordsOneIndependentFailure() {
        doThrow(new IllegalStateException("unsafe-storage-details"))
                .when(recorder).appendInCurrentTransaction(any());
        assertThatThrownBy(service::transactionalSuccess).isInstanceOf(AuditUnavailableException.class);
        assertThat(independent).extracting(AuditEvent::phase)
                .containsExactly(AuditPhase.STARTED, AuditPhase.FAILED);
        assertThat(independent.getLast().outcomeType()).isEqualTo("AUDIT_UNAVAILABLE");
        assertThat(committed).isEmpty();
    }

    @Test
    void partialTransactionalAppendCannotDeadlockOnItsOwnUncommittedTerminalIdentifier() {
        doAnswer(invocation -> {
            transactional.add(invocation.getArgument(0));
            throw new IllegalStateException("Failure after the database insert");
        }).when(recorder).appendInCurrentTransaction(any());
        doAnswer(invocation -> {
            AuditEvent event = invocation.getArgument(0);
            if (event.phase() == AuditPhase.FAILED) {
                assertThat(transactions.completed).as("unique-key owner must have finished before retry").isTrue();
                assertThat(event.id()).isEqualTo(transactional.getFirst().id());
            }
            independent.add(event);
            return null;
        }).when(recorder).appendIndependent(any());
        assertThatThrownBy(service::transactionalSuccess).isInstanceOf(AuditUnavailableException.class);
        assertThat(independent).extracting(AuditEvent::phase)
                .containsExactly(AuditPhase.STARTED, AuditPhase.FAILED);
    }

    @Test
    void rollbackCallbackFailureCannotMaskTheAlreadyCompletedTransaction() {
        doAnswer(invocation -> {
            AuditEvent event = invocation.getArgument(0);
            if (event.phase() == AuditPhase.FAILED) throw new IllegalStateException("secret");
            independent.add(event);
            return null;
        }).when(recorder).appendIndependent(any());
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            service.transactionalSuccess();
            status.setRollbackOnly();
        });
        assertThat(independent).extracting(AuditEvent::phase).containsExactly(AuditPhase.STARTED);
        assertThat(committed).isEmpty();
    }

    @Test
    void noRequestOrUnrecognizedPrincipalUsesAnonymousWithoutCallingPrincipalToString() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(AuditedService.OPAQUE_RESULT, null, List.of()));
        service.perform("email@example.com", "password");
        assertThat(independent.getFirst().actorId()).isEqualTo("anonymous");
        assertThat(independent.getFirst().remoteAddress()).isEmpty();
        assertThat(independent.getFirst().requestPath()).isEmpty();
    }

    @Test
    void callerThreadSnapshotDoesNotLeakIntoTheNextInvocation() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/test");
        request.setRemoteAddr("10.2.3.4");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        service.perform("one", null);
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
        service.perform("two", null);
        assertThat(independent.get(0).actorId()).isEqualTo(USER_ID.toString());
        assertThat(independent.get(2).actorId()).isEqualTo("anonymous");
        assertThat(independent.get(2).requestPath()).isEmpty();
        assertThat(independent.get(2).invocationId()).isNotEqualTo(independent.get(0).invocationId());
    }

    @Test
    void unannotatedMethodsDoNotGenerateEvents() {
        assertThat(service.count()).isZero();
        verifyNoInteractions(recorder);
    }

    private static void authenticate() {
        IamPrincipal principal = new IamPrincipal(USER_ID, "secret@example.com", "Engineering",
                (short) 1, Set.of(), Set.of());
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.authorities()));
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAspectJAutoProxy
    @EnableMethodSecurity
    @EnableTransactionManagement(order = 0)
    @Import(AuditAspect.class)
    static class Config {
        @Bean AuditRecorder recorder() { return mock(AuditRecorder.class); }
        @Bean Clock clock() { return Clock.fixed(NOW, ZoneOffset.UTC); }
        @Bean AuditedService service() { return new AuditedService(); }
        @Bean TestTransactionManager transactionManager() { return new TestTransactionManager(); }
    }

    static class AuditedService {
        static final Object OPAQUE_RESULT = new Object() {
            @Override public String toString() { throw new AssertionError("Sensitive object was stringified"); }
        };
        private int count;
        public int count() { return count; }
        public void resetCount() { count = 0; }
        @AuditAction(action = "TEST_PERFORM")
        public Object perform(String password, Object opaque) { count++; return OPAQUE_RESULT; }
        @AuditAction(action = "TEST_FAILURE")
        public void fail(RuntimeException failure) { throw failure; }
        @AuditAction(action = "TEST_DENIED")
        @PreAuthorize("denyAll()")
        public void denied() { count++; }
        @AuditAction(action = "TEST_TRANSACTION")
        @Transactional
        public void transactionalSuccess() {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            count++;
        }
    }

    static class TestTransactionManager extends AbstractPlatformTransactionManager {
        boolean failCommit;
        boolean completed;
        @Override protected Object doGetTransaction() {
            return TransactionSynchronizationManager.isActualTransactionActive();
        }
        @Override protected boolean isExistingTransaction(Object transaction) {
            return Boolean.TRUE.equals(transaction);
        }
        @Override protected void doBegin(Object transaction, TransactionDefinition definition) { completed = false; }
        @Override protected void doCommit(DefaultTransactionStatus status) {
            completed = true;
            if (failCommit) throw new TransactionSystemException("Commit outcome unavailable");
        }
        @Override protected void doRollback(DefaultTransactionStatus status) { completed = true; }
        @Override protected void doSetRollbackOnly(DefaultTransactionStatus status) { }
    }
}
