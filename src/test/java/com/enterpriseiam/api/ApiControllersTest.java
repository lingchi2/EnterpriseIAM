package com.enterpriseiam.api;

import static com.enterpriseiam.security.jwt.JwtTestSupport.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.enterpriseiam.api.auth.AuthController;
import com.enterpriseiam.api.auth.LoginRequest;
import com.enterpriseiam.api.auth.RefreshRequest;
import com.enterpriseiam.api.auth.TokenResponse;
import com.enterpriseiam.api.auth.TokenResponseMapper;
import com.enterpriseiam.api.resource.ResourceController;
import com.enterpriseiam.api.resource.ResourceResponse;
import com.enterpriseiam.api.resource.ResourceResponseMapper;
import com.enterpriseiam.api.resource.ResourceUpdateRequest;
import com.enterpriseiam.resource.ResourceReference;
import com.enterpriseiam.resource.ResourceService;
import com.enterpriseiam.resource.ResourceSnapshot;
import com.enterpriseiam.security.auth.AuthenticationService;
import com.enterpriseiam.security.auth.TokenPair;
import com.enterpriseiam.security.config.SecurityConfiguration;
import com.enterpriseiam.security.identity.IdentityDirectory;
import com.enterpriseiam.security.identity.IamPrincipal;
import com.enterpriseiam.security.jwt.IamJwtAuthenticationConverter;
import com.enterpriseiam.security.jwt.IamJwtAuthenticationToken;
import com.enterpriseiam.security.ratelimit.AuthenticationRateLimitFilter;
import com.enterpriseiam.api.web.RequestBodyLimitFilter;
import com.enterpriseiam.security.ratelimit.AuthenticationRateLimiter;
import com.enterpriseiam.security.ratelimit.RateLimitDecision;
import com.enterpriseiam.security.redis.AccessTokenBlacklist;
import com.enterpriseiam.security.tokens.SessionRegistry;
import com.enterpriseiam.security.web.SecurityExceptionHandler;
import com.enterpriseiam.security.web.SecurityProblemSupport;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mapstruct.factory.Mappers;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(properties = "spring.jackson.deserialization.fail-on-unknown-properties=true")
@ContextConfiguration(classes = {AuthController.class, ResourceController.class,
        ApiControllersTest.TestSecurity.class, SecurityConfiguration.class, SecurityProblemSupport.class,
        SecurityExceptionHandler.class, IamJwtAuthenticationConverter.class, AuthenticationRateLimitFilter.class,
        RequestBodyLimitFilter.class})
class ApiControllersTest {
    private static final UUID RESOURCE_ID = UUID.randomUUID();
    private static final String REFRESH_TOKEN = "A".repeat(43);
    private static final TokenPair TOKENS = new TokenPair("access-secret", REFRESH_TOKEN,
            NOW.plusSeconds(300), NOW.plusSeconds(3600));
    @Autowired private MockMvc mvc;
    @MockBean private AuthenticationService authentication;
    @MockBean private ResourceService resources;
    @MockBean private AuthenticationRateLimiter rateLimiter;
    @MockBean private IdentityDirectory identities;
    @MockBean private SessionRegistry sessions;
    @MockBean private AccessTokenBlacklist blacklist;
    @MockBean private UserDetailsService users;
    private String accessHeader;

    @BeforeEach
    void prepare() {
        accessHeader = "Bearer " + signed(builder -> { });
        when(sessions.isActive(USER_ID, SESSION_ID)).thenReturn(true);
        when(identities.requireActive(USER_ID)).thenReturn(new IamPrincipal(USER_ID, "user@example.test", "Finance",
                (short) 2, Set.of("ANALYST"), Set.of("RESOURCE:READ", "RESOURCE:WRITE")));
        when(rateLimiter.check(anyString(), anyString())).thenReturn(new RateLimitDecision(true, 0));
    }

    @Test
    void loginPreservesPasswordAndUsesGeneratedMapperWithoutCookiesOrCaching() throws Exception {
        when(authentication.login("user@example.test", "  exact password  ")).thenReturn(TOKENS);
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"user@example.test\",\"password\":\"  exact password  \"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.accessToken").value("access-secret"))
                .andExpect(jsonPath("$.refreshToken").value(REFRESH_TOKEN))
                .andExpect(jsonPath("$.accessTokenExpiresAt").value(NOW.plusSeconds(300).toString()))
                .andExpect(jsonPath("$.refreshTokenExpiresAt").value(NOW.plusSeconds(3600).toString()))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andExpect(result -> assertThat(result.getRequest().getSession(false)).isNull());
        verify(authentication).login("user@example.test", "  exact password  ");
        verify(rateLimiter).check("127.0.0.1", "login");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{}", "{\"email\":\"not-email\",\"password\":\"secret\"}",
            "{\"email\":\"user@example.test\",\"password\":null}",
            "{\"email\":\"user@example.test\",\"password\":\"  \"}",
            "{\"email\":\"user@example.test\",\"password\":\"secret\",\"roles\":[\"ADMIN\"]}",
            "{\"email\":\"user@example.test\",\"password\":"})
    void malformedLoginIsProblem400BeforeCredentialVerification(String body) throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest()).andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
                .andExpect(content().string(not(containsString("secret"))));
        verifyNoInteractions(authentication);
    }

    @Test
    void credentialsRejectionReturnsGenericProblemWithoutEchoingInput() throws Exception {
        when(authentication.login(anyString(), anyString()))
                .thenThrow(new BadCredentialsException("user@example.test supplied highly-secret"));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"user@example.test\",\"password\":\"highly-secret\"}"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.status").value(401))
                .andExpect(content().string(not(containsString("highly-secret"))))
                .andExpect(content().string(not(containsString("user@example.test"))));
    }

    @Test
    void refreshRotatesExactOpaqueTokenAndReturnsNoStoreResponse() throws Exception {
        when(authentication.refresh(REFRESH_TOKEN)).thenReturn(TOKENS);
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + REFRESH_TOKEN + "\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").value("access-secret"))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"));
        verify(authentication).refresh(REFRESH_TOKEN);
        verify(rateLimiter).check("127.0.0.1", "refresh");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "abc", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", " AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
    void malformedRefreshIsRejectedBeforeService(String token) throws Exception {
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + token + "\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400));
        verifyNoInteractions(authentication);
    }

    @Test
    void logoutPassesVerifiedAuthenticationAndReturns204() throws Exception {
        mvc.perform(post("/api/v1/auth/logout").header(HttpHeaders.AUTHORIZATION, accessHeader))
                .andExpect(status().isNoContent()).andExpect(content().string(""))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"));
        ArgumentCaptor<IamJwtAuthenticationToken> principal = ArgumentCaptor.forClass(IamJwtAuthenticationToken.class);
        verify(authentication).logout(principal.capture());
        assertThat(principal.getValue().getPrincipal().userId()).isEqualTo(USER_ID);
        assertThat(principal.getValue().getToken().getId()).isEqualTo(TOKEN_ID.toString());
        verifyNoInteractions(rateLimiter);
    }

    @Test
    void unauthenticatedLogoutCannotRevokeSession() throws Exception {
        mvc.perform(post("/api/v1/auth/logout"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.status").value(401))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"));
        verifyNoInteractions(authentication);
    }

    @Test
    void readMapsAuthorizedSnapshotWithoutExposingAnEntity() throws Exception {
        when(resources.read(new ResourceReference(RESOURCE_ID))).thenReturn(snapshot("authorized content", 7));
        mvc.perform(get("/api/v1/resources/{id}", RESOURCE_ID).header(HttpHeaders.AUTHORIZATION, accessHeader))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(RESOURCE_ID.toString()))
                .andExpect(jsonPath("$.ownerId").value(USER_ID.toString()))
                .andExpect(jsonPath("$.department").value("Finance"))
                .andExpect(jsonPath("$.classification").value(2))
                .andExpect(jsonPath("$.content").value("authorized content"))
                .andExpect(jsonPath("$.version").value(7));
        verify(resources).read(new ResourceReference(RESOURCE_ID));
    }

    @Test
    void updateUsesPathIdentityAndExplicitExpectedVersion() throws Exception {
        when(resources.write(new ResourceReference(RESOURCE_ID), "updated", 7)).thenReturn(snapshot("updated", 8));
        mvc.perform(put("/api/v1/resources/{id}", RESOURCE_ID).header(HttpHeaders.AUTHORIZATION, accessHeader)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"content\":\"updated\",\"expectedVersion\":7}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.content").value("updated"))
                .andExpect(jsonPath("$.version").value(8));
        verify(resources).write(new ResourceReference(RESOURCE_ID), "updated", 7);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{}", "{\"content\":\"secret\"}", "{\"content\":null,\"expectedVersion\":0}",
            "{\"content\":\"secret\",\"expectedVersion\":-1}",
            "{\"content\":\"secret\",\"expectedVersion\":0,\"department\":\"Admin\"}",
            "{\"content\":\"secret\",\"expectedVersion\":0,\"classification\":0}",
            "{\"content\":\"secret\",\"expectedVersion\":0,\"ownerId\":\"attacker\"}"})
    void invalidUpdateOrCallerSuppliedSecurityAttributesCannotReachService(String body) throws Exception {
        mvc.perform(put("/api/v1/resources/{id}", RESOURCE_ID).header(HttpHeaders.AUTHORIZATION, accessHeader)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400))
                .andExpect(content().string(not(containsString("secret"))));
        verifyNoInteractions(resources);
    }

    @Test
    void oversizedResourceContentIsRejectedBeforeService() throws Exception {
        mvc.perform(put("/api/v1/resources/{id}", RESOURCE_ID).header(HttpHeaders.AUTHORIZATION, accessHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"content\":\"" + "x".repeat(1_048_577) + "\",\"expectedVersion\":0}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400));
        verifyNoInteractions(resources);
    }

    @Test
    void malformedResourceIdIsProblem400() throws Exception {
        mvc.perform(get("/api/v1/resources/not-a-uuid").header(HttpHeaders.AUTHORIZATION, accessHeader))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400));
        verifyNoInteractions(resources);
    }

    @Test
    void serviceAuthorizationDenialIsProblem403WithoutPolicyAttributes() throws Exception {
        when(resources.read(any())).thenThrow(new AccessDeniedException("sensitive classification details"));
        mvc.perform(get("/api/v1/resources/{id}", RESOURCE_ID).header(HttpHeaders.AUTHORIZATION, accessHeader))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.status").value(403))
                .andExpect(content().string(not(containsString("classification"))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"login", "refresh"})
    void throttleRejectsBeforeDeserializationOrService(String endpoint) throws Exception {
        when(rateLimiter.check("127.0.0.1", endpoint)).thenReturn(new RateLimitDecision(false, 17));
        mvc.perform(post("/api/v1/auth/" + endpoint).contentType(MediaType.APPLICATION_JSON).content("not-json"))
                .andExpect(status().isTooManyRequests()).andExpect(jsonPath("$.status").value(429))
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, "17"))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"));
        verifyNoInteractions(authentication);
    }

    @Test
    void redisLimiterFailureFailsClosedWithoutLeakingDependencyDetails() throws Exception {
        when(rateLimiter.check(anyString(), anyString()))
                .thenThrow(new AuthenticationServiceException("private redis hostname"));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.status").value(503))
                .andExpect(content().string(not(containsString("hostname"))));
        verifyNoInteractions(authentication);
    }

    @Test
    void diagnosticStringsNeverIncludeCredentialsOrResourceBodies() {
        assertThat(new LoginRequest("personal@example.test", "private-password").toString())
                .doesNotContain("personal@example.test", "private-password");
        assertThat(new RefreshRequest("private-refresh").toString()).doesNotContain("private-refresh");
        assertThat(new TokenResponse("Bearer", "private-access", "private-refresh", NOW, NOW).toString())
                .doesNotContain("private-access", "private-refresh");
        assertThat(new ResourceUpdateRequest("private-content", 0L).toString()).doesNotContain("private-content");
        assertThat(new ResourceResponse(RESOURCE_ID, USER_ID, "private-department", (short) 2,
                "private-content", 0).toString()).doesNotContain("private-content", "private-department");
    }

    private static ResourceSnapshot snapshot(String content, long version) {
        return new ResourceSnapshot(RESOURCE_ID, USER_ID, "Finance", (short) 2, content, version);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class TestSecurity {
        @Bean JwtDecoder jwtDecoder() { return DECODER; }
        @Bean TokenResponseMapper tokenResponseMapper() { return Mappers.getMapper(TokenResponseMapper.class); }
        @Bean ResourceResponseMapper resourceResponseMapper() { return Mappers.getMapper(ResourceResponseMapper.class); }
    }
}
