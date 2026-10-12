package com.enterpriseiam.security.web;

import static com.enterpriseiam.security.jwt.JwtTestSupport.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.enterpriseiam.security.config.SecurityConfiguration;
import com.enterpriseiam.api.web.RequestBodyLimitFilter;
import com.enterpriseiam.security.identity.IdentityDirectory;
import com.enterpriseiam.security.identity.IamPrincipal;
import com.enterpriseiam.security.jwt.IamJwtAuthenticationConverter;
import com.enterpriseiam.security.ratelimit.AuthenticationRateLimitFilter;
import com.enterpriseiam.security.ratelimit.AuthenticationRateLimiter;
import com.enterpriseiam.security.ratelimit.RateLimitDecision;
import com.enterpriseiam.security.redis.AccessTokenBlacklist;
import com.enterpriseiam.security.tokens.SessionRegistry;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@WebMvcTest
@ContextConfiguration(classes = {SecurityFilterChainTest.Endpoints.class, SecurityFilterChainTest.TestSecurity.class,
        SecurityConfiguration.class, SecurityProblemSupport.class, SecurityExceptionHandler.class,
        IamJwtAuthenticationConverter.class, AuthenticationRateLimitFilter.class, RequestBodyLimitFilter.class})
class SecurityFilterChainTest {
    @Autowired private MockMvc mvc;
    @MockBean private IdentityDirectory identities;
    @MockBean private SessionRegistry sessions;
    @MockBean private AccessTokenBlacklist blacklist;
    @MockBean private UserDetailsService users;
    @MockBean private AuthenticationRateLimiter rateLimiter;
    private String token;

    @BeforeEach
    void prepare() {
        when(rateLimiter.check(anyString(), anyString())).thenReturn(new RateLimitDecision(true, 0));
        token = signed(builder -> {});
        when(sessions.isActive(USER_ID, SESSION_ID)).thenReturn(true);
        when(identities.requireActive(USER_ID)).thenReturn(new IamPrincipal(USER_ID, "user@example.test", "Finance",
                (short) 2, Set.of("ANALYST"), Set.of("RESOURCE:READ")));
    }

    @Test
    void missingAndInvalidBearerReturnProblemDetailsWithChallenge() throws Exception {
        mvc.perform(get("/api/v1/test"))
                .andExpect(status().isUnauthorized()).andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                .andExpect(jsonPath("$.status").value(401)).andExpect(jsonPath("$.type").value("about:blank"));
        mvc.perform(get("/api/v1/test").header(HttpHeaders.AUTHORIZATION, "Bearer not.a.jwt"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.title").value("Unauthorized"));
    }

    @Test
    void validBearerNeverCreatesHttpSessionOrPersistsAuthentication() throws Exception {
        mvc.perform(get("/api/v1/test").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk()).andExpect(header().doesNotExist("Set-Cookie"))
                .andExpect(result -> assertThat(result.getRequest().getSession(false)).isNull());
        mvc.perform(get("/api/v1/test")).andExpect(status().isUnauthorized());
    }

    @Test
    void methodSecurityDenialAndFilterDenialShareProblemRepresentation() throws Exception {
        mvc.perform(get("/api/v1/admin").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden()).andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(403)).andExpect(jsonPath("$.title").value("Forbidden"));
        mvc.perform(get("/outside-api").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.status").value(403));
    }

    @Test
    void redisOutageIsProblem503AndNeverReachesController() throws Exception {
        when(blacklist.isRevoked(TOKEN_ID)).thenThrow(new AuthenticationServiceException("sensitive Redis hostname"));
        mvc.perform(get("/api/v1/test").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isServiceUnavailable()).andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(503)).andExpect(header().string(HttpHeaders.RETRY_AFTER, "5"))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("hostname"))));
        verifyNoInteractions(identities, sessions);
    }

    @Test
    void revocationIsEnforcedInTheActualFilterChain() throws Exception {
        when(blacklist.isRevoked(TOKEN_ID)).thenReturn(true);
        mvc.perform(get("/api/v1/test").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void databaseTransactionCannotStartReturnsProblem503() throws Exception {
        when(identities.requireActive(USER_ID)).thenThrow(new CannotCreateTransactionException("sensitive database hostname"));
        mvc.perform(get("/api/v1/test").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isServiceUnavailable()).andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(503))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("hostname"))));
    }

    @Test
    void queryTokensCookiesAndBasicAuthenticationCannotAuthenticate() throws Exception {
        mvc.perform(get("/api/v1/test").param("access_token", token))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/test").cookie(new jakarta.servlet.http.Cookie("access_token", token)))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/test").header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void publicLoginRouteCanReportGenericAuthenticationProblemThroughAdvice() throws Exception {
        mvc.perform(post("/api/v1/auth/login"))
                .andExpect(status().isUnauthorized()).andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                .andExpect(jsonPath("$.detail").value("Authentication is required or the supplied credentials are invalid."));
        mvc.perform(get("/api/v1/auth/login")).andExpect(status().isUnauthorized());
    }

    @Test
    void optimisticVersionConflictReturns409WithoutLeakingEntityDetails() throws Exception {
        mvc.perform(post("/api/v1/test/conflict").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isConflict()).andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(409)).andExpect(jsonPath("$.title").value("Conflict"))
                .andExpect(jsonPath("$.detail").value("The resource changed since it was read. Reload it and retry the operation."))
                .andExpect(header().doesNotExist(HttpHeaders.RETRY_AFTER))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("SensitiveEntity"))));
    }

    @TestConfiguration(proxyBeanMethods = false)
    @EnableMethodSecurity
    static class TestSecurity {
        @Bean JwtDecoder jwtDecoder() { return DECODER; }
    }

    @RestController
    static class Endpoints {
        @GetMapping("/api/v1/test") Map<String, String> authenticated() { return Map.of("result", "ok"); }
        @GetMapping("/api/v1/admin") @PreAuthorize("hasRole('ADMIN')")
        Map<String, String> admin() { return Map.of("result", "ok"); }
        @PostMapping("/api/v1/auth/login") void login() { throw new BadCredentialsException("sensitive login reason"); }
        @PostMapping("/api/v1/test/conflict") void conflict() {
            throw new ObjectOptimisticLockingFailureException("SensitiveEntity", USER_ID);
        }
    }
}
