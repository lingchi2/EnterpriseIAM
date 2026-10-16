package com.enterpriseiam.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.enterpriseiam.resource.ResourceOperations;
import com.enterpriseiam.resource.ResourceReference;
import com.enterpriseiam.resource.ResourceRepository;
import com.enterpriseiam.resource.ResourceService;
import com.enterpriseiam.resource.SecuredResource;
import com.enterpriseiam.security.identity.IamPrincipal;
import com.enterpriseiam.security.identity.IdentityDirectory;
import jakarta.persistence.EntityManager;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@SpringJUnitConfig(ResourceMethodSecurityTest.Config.class)
@TestPropertySource(properties = "iam.abac.allowed-cidrs=10.0.0.0/8")
class ResourceMethodSecurityTest {
    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID RESOURCE_ID = UUID.randomUUID();
    private static final ResourceReference REFERENCE = new ResourceReference(RESOURCE_ID);

    @Autowired ResourceService service;
    @Autowired ResourceOperations operations;
    @Autowired ResourceRepository repository;
    @Autowired IdentityDirectory identities;
    @Autowired AbacPermissionEvaluator evaluator;
    @Autowired PlatformTransactionManager transactions;
    @Autowired EntityManager entityManager;
    @Autowired Clock clock;
    private SecuredResource resource;
    private IamPrincipal principal;

    @BeforeEach
    void setUp() {
        reset(repository, identities, entityManager, clock);
        when(clock.instant()).thenReturn(Instant.parse("2026-10-23T12:00:00Z"));
        when(clock.getZone()).thenReturn(ZoneOffset.UTC);
        principal = principal("Engineering", (short) 2, Set.of("RESOURCE:READ", "RESOURCE:WRITE"));
        authenticate(principal);
        when(identities.requireActive(USER_ID)).thenReturn(principal);
        resource = resource(USER_ID, "Engineering", (short) 2);
        when(repository.findForRead(RESOURCE_ID)).thenAnswer(invocation -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            return Optional.of(resource);
        });
        when(repository.findForWrite(RESOURCE_ID)).thenAnswer(invocation -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            return Optional.of(resource);
        });
        when(repository.findById(RESOURCE_ID)).thenReturn(Optional.of(resource));
        doAnswer(invocation -> {
            ReflectionTestUtils.setField(resource, "version", 1L);
            return null;
        }).when(repository).flush();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.1.2.3");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void clearContexts() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void actualServiceProxiesAuthorizeBeforeReadingAndWritingUnderTheSameTransaction() {
        assertThat(AopUtils.isAopProxy(service)).isTrue();
        assertThat(AopUtils.isAopProxy(operations)).isTrue();
        assertThat(service.read(REFERENCE).content()).isEqualTo("original");
        var result = service.write(REFERENCE, "changed", 0);
        assertThat(result.content()).isEqualTo("changed");
        assertThat(result.version()).isEqualTo(1);
        verify(repository).findForRead(RESOURCE_ID);
        verify(repository).findForWrite(RESOURCE_ID);
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
    }

    @Test
    void staleTokenAuthoritiesCannotOverrideCurrentPermissionRevocation() {
        when(identities.requireActive(USER_ID)).thenReturn(principal("Engineering", (short) 4, Set.of()));
        assertThatThrownBy(() -> service.read(REFERENCE)).isInstanceOf(AccessDeniedException.class);
        verify(repository, never()).findById(any());
        verify(repository).findForRead(RESOURCE_ID);
    }

    @Test
    void grantRevocationWhileWaitingForTheResourceLockAppliesToThisDecision() {
        doAnswer(invocation -> {
            when(identities.requireActive(USER_ID)).thenReturn(principal("Engineering", (short) 2, Set.of()));
            return Optional.of(resource);
        }).when(repository).findForRead(RESOURCE_ID);

        assertThatThrownBy(() -> service.read(REFERENCE)).isInstanceOf(AccessDeniedException.class);
        verify(repository, never()).findById(any());
    }

    @Test
    void businessHoursClosingWhileWaitingForTheResourceLockAppliesToThisDecision() {
        doAnswer(invocation -> {
            when(clock.instant()).thenReturn(Instant.parse("2026-10-23T17:00:00Z"));
            return Optional.of(resource);
        }).when(repository).findForRead(RESOURCE_ID);

        assertThatThrownBy(() -> service.read(REFERENCE)).isInstanceOf(AccessDeniedException.class);
        verify(repository, never()).findById(any());
    }

    @Test
    void liveAttributeChangesAreAppliedBetweenInvocations() {
        assertThat(service.read(REFERENCE).content()).isEqualTo("original");
        when(identities.requireActive(USER_ID)).thenReturn(principal("Engineering", (short) 1,
                Set.of("RESOURCE:READ", "RESOURCE:WRITE")));
        assertThatThrownBy(() -> service.write(REFERENCE, "forbidden", 0))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(resource.getContent()).isEqualTo("original");
        verify(repository, never()).flush();
    }

    @Test
    void missingOrInactiveSubjectCannotExecuteProtectedMethod() {
        when(identities.requireActive(USER_ID)).thenThrow(new BadCredentialsException("Unknown account"));
        assertThatThrownBy(() -> service.read(REFERENCE)).isInstanceOf(AccessDeniedException.class);
        verify(repository, never()).findById(any());
    }

    @Test
    void outagesFailClosedAndRemainInfrastructureFailures() {
        doThrow(new DataAccessResourceFailureException("Database down"))
                .when(repository).findForRead(RESOURCE_ID);
        assertThatThrownBy(() -> service.read(REFERENCE)).isInstanceOf(AuthenticationServiceException.class);
        verify(repository, never()).findById(any());
        when(identities.requireActive(USER_ID)).thenThrow(new AuthenticationServiceException("Directory down"));
        assertThatThrownBy(() -> service.write(REFERENCE, "forbidden", 0))
                .isInstanceOf(AuthenticationServiceException.class);
        verify(repository, never()).flush();
    }

    @Test
    void wrongOwnerCannotWriteEvenWithSameDepartmentAndPermission() {
        resource = resource(UUID.randomUUID(), "Engineering", (short) 2);
        assertThatThrownBy(() -> service.write(REFERENCE, "forbidden", 0))
                .isInstanceOf(AccessDeniedException.class);
        verify(repository, never()).findById(any());
        verify(repository, never()).flush();
    }

    @Test
    void missingResourceMissingRequestAndSpoofedNetworkCannotExecuteProtectedMethod() {
        doReturn(Optional.empty()).when(repository).findForRead(RESOURCE_ID);
        assertThatThrownBy(() -> service.read(REFERENCE)).isInstanceOf(AccessDeniedException.class);
        doReturn(Optional.of(resource)).when(repository).findForRead(RESOURCE_ID);
        RequestContextHolder.resetRequestAttributes();
        assertThatThrownBy(() -> service.read(REFERENCE)).isInstanceOf(AccessDeniedException.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.5");
        request.addHeader("X-Forwarded-For", "10.1.2.3");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        assertThatThrownBy(() -> service.read(REFERENCE)).isInstanceOf(AccessDeniedException.class);
        verify(repository, never()).findById(any());
    }

    @Test
    void forgedEntityMetadataIsIgnoredInFavorOfLockedDatabaseAttributes() {
        resource = resource(UUID.randomUUID(), "Finance", (short) 4);
        var forged = resource(USER_ID, "Engineering", (short) 0);
        assertThat(inTransaction(() -> evaluator.hasPermission(authentication(), forged, "READ"))).isFalse();
        verify(repository).findForRead(RESOURCE_ID);
    }

    @Test
    void identifierOverloadIsSupportedAndUnknownInputsDeny() {
        assertThat(inTransaction(() -> evaluator.hasPermission(authentication(), RESOURCE_ID, "RESOURCE", "READ")))
                .isTrue();
        assertThat(evaluator.hasPermission(authentication(), RESOURCE_ID, "USER", "READ")).isFalse();
        assertThat(evaluator.hasPermission(authentication(), RESOURCE_ID.toString(), "RESOURCE", "READ")).isFalse();
        assertThat(evaluator.hasPermission(authentication(), (Object) null, "READ")).isFalse();
        assertThat(evaluator.hasPermission(authentication(), new ResourceReference(null), "READ")).isFalse();
        assertThat(evaluator.hasPermission(authentication(), new Object(), "READ")).isFalse();
        assertThat(evaluator.hasPermission(authentication(), REFERENCE, "DELETE")).isFalse();
        assertThat(evaluator.hasPermission(authentication(), REFERENCE, "read")).isFalse();
        assertThat(evaluator.hasPermission(authentication(), REFERENCE, null)).isFalse();
        assertThat(evaluator.hasPermission(authentication(), REFERENCE, 1)).isFalse();
    }

    @Test
    void anonymousUnauthenticatedAndMissingIdentityDeny() {
        assertThat(evaluator.hasPermission(null, REFERENCE, "READ")).isFalse();
        var anonymous = new AnonymousAuthenticationToken("key", principal, principal.authorities());
        assertThat(evaluator.hasPermission(anonymous, REFERENCE, "READ")).isFalse();
        var unauthenticated = UsernamePasswordAuthenticationToken.unauthenticated(principal, null);
        assertThat(evaluator.hasPermission(unauthenticated, REFERENCE, "READ")).isFalse();
        var wrongPrincipal = UsernamePasswordAuthenticationToken.authenticated("user", null, principal.authorities());
        assertThat(evaluator.hasPermission(wrongPrincipal, REFERENCE, "READ")).isFalse();
    }

    @Test
    void directProtectedOperationOutsideTransactionIsDeniedBeforeItsBodyRuns() {
        assertThatThrownBy(() -> operations.read(REFERENCE)).isInstanceOf(AccessDeniedException.class);
        verify(repository, never()).findForRead(any());
        verify(repository, never()).findById(any());
    }

    @Test
    void staleWriteVersionCannotOverwriteContent() {
        assertThatThrownBy(() -> service.write(REFERENCE, "forbidden", 10))
                .isInstanceOf(ObjectOptimisticLockingFailureException.class);
        assertThat(resource.getContent()).isEqualTo("original");
        verify(repository, never()).flush();
    }

    private boolean inTransaction(Supplier<Boolean> decision) {
        return Boolean.TRUE.equals(new TransactionTemplate(transactions).execute(status -> decision.get()));
    }

    private static SecuredResource resource(UUID owner, String department, short classification) {
        SecuredResource resource = SecuredResource.create(owner, department, classification, "original");
        ReflectionTestUtils.setField(resource, "id", RESOURCE_ID);
        ReflectionTestUtils.setField(resource, "version", 0L);
        return resource;
    }

    private static IamPrincipal principal(String department, short clearance, Set<String> permissions) {
        return new IamPrincipal(USER_ID, "analyst@example.com", department, clearance, Set.of("ADMIN"), permissions);
    }

    private static void authenticate(IamPrincipal principal) {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.authorities()));
    }

    private static org.springframework.security.core.Authentication authentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableTransactionManagement
    @Import({MethodSecurityConfiguration.class, AbacPermissionEvaluator.class, DefaultAbacPolicy.class,
            SubjectAttributeResolver.class, ResourceAttributeResolver.class, EnvironmentAttributeResolver.class,
            ResourceService.class, ResourceOperations.class})
    static class Config {
        @Bean IdentityDirectory identities() { return mock(IdentityDirectory.class); }
        @Bean ResourceRepository resources() { return mock(ResourceRepository.class); }
        @Bean EntityManager entityManager() { return mock(EntityManager.class); }
        @Bean Clock clock() { return mock(Clock.class); }
        @Bean PlatformTransactionManager transactionManager() { return new TestTransactionManager(); }
    }

    /** Exercises Spring transaction interception; real row locks are covered by ResourceAuthorizationIT. */
    static class TestTransactionManager extends AbstractPlatformTransactionManager {
        @Override protected Object doGetTransaction() {
            return TransactionSynchronizationManager.isActualTransactionActive();
        }
        @Override protected boolean isExistingTransaction(Object transaction) {
            return Boolean.TRUE.equals(transaction);
        }
        @Override protected void doBegin(Object transaction, TransactionDefinition definition) { }
        @Override protected void doCommit(DefaultTransactionStatus status) { }
        @Override protected void doRollback(DefaultTransactionStatus status) { }
        @Override protected void doSetRollbackOnly(DefaultTransactionStatus status) { }
    }
}
