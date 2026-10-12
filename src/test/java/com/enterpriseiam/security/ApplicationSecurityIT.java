package com.enterpriseiam.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.enterpriseiam.security.jwt.JwtTestSupport;
import com.enterpriseiam.security.ratelimit.AuthenticationRateLimiter;
import com.enterpriseiam.security.ratelimit.RateLimitDecision;
import com.enterpriseiam.security.redis.AccessTokenBlacklist;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.containers.PostgreSQLContainer;

/** Production HTTP controllers, JWT, method security, JPA transactions, and durable audit ledger. */
@SpringBootTest(properties = {
        "spring.data.redis.host=127.0.0.1", "spring.data.redis.username=test",
        "spring.data.redis.password=test", "spring.data.redis.ssl.enabled=false",
        "spring.elasticsearch.uris=http://127.0.0.1:9200",
        "spring.elasticsearch.username=test", "spring.elasticsearch.password=test",
        "iam.abac.allowed-cidrs=10.20.0.0/16", "iam.abac.zone-id=UTC",
        "iam.auth.rate-limit.key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "iam.audit.dispatcher-enabled=false"
})
@AutoConfigureMockMvc
@Import(ApplicationSecurityIT.FixedClock.class)
class ApplicationSecurityIT {
    private static PostgreSQLContainer<?> postgres;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        String url = System.getenv("IAM_TEST_DB_URL");
        String username = System.getenv("IAM_TEST_DB_USERNAME");
        String password = System.getenv("IAM_TEST_DB_PASSWORD");
        if (url == null) {
            postgres = new PostgreSQLContainer<>("postgres:16.9-alpine");
            postgres.start();
            url = postgres.getJdbcUrl();
            username = postgres.getUsername();
            password = postgres.getPassword();
        }
        if (url.isBlank() || username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new IllegalArgumentException("Explicit test database requires URL, username and password");
        }
        String jdbcUrl = url;
        String dbUser = username;
        String dbPassword = password;
        registry.add("spring.datasource.url", () -> jdbcUrl);
        registry.add("spring.datasource.username", () -> dbUser);
        registry.add("spring.datasource.password", () -> dbPassword);
        registry.add("spring.flyway.url", () -> jdbcUrl);
        registry.add("spring.flyway.user", () -> dbUser);
        registry.add("spring.flyway.password", () -> dbPassword);
        registry.add("iam.security.issuer", () -> JwtTestSupport.PROPERTIES.issuer());
        registry.add("iam.security.audience", () -> JwtTestSupport.PROPERTIES.audience());
        registry.add("iam.security.key-id", () -> JwtTestSupport.PROPERTIES.keyId());
        registry.add("iam.security.private-key", () -> JwtTestSupport.PROPERTIES.privateKey());
        registry.add("iam.security.public-key", () -> JwtTestSupport.PROPERTIES.publicKey());
    }

    @AfterAll
    static void closeDatabase() {
        if (postgres != null) postgres.stop();
    }

    private static final String PASSWORD = "correct-password";
    private static final String ORIGINAL_CONTENT = "classified payload";
    @Autowired private MockMvc mvc;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PasswordEncoder encoder;
    @Autowired private JwtDecoder decoder;
    @Autowired private ObjectMapper mapper;
    @MockBean private AccessTokenBlacklist blacklist;
    @MockBean private AuthenticationRateLimiter rateLimiter;
    private UUID userId;
    private UUID roleId;
    private UUID resourceId;
    private String email;
    private String auditMarker;

    @BeforeEach
    void fixtures() {
        userId = UUID.randomUUID();
        roleId = UUID.randomUUID();
        resourceId = UUID.randomUUID();
        email = userId + "@example.com";
        auditMarker = "security-integration-" + UUID.randomUUID();
        when(blacklist.isRevoked(any())).thenReturn(false);
        when(rateLimiter.check(any(), any())).thenReturn(new RateLimitDecision(true, 0));
        jdbc.update("""
                INSERT INTO iam.users (id, email, password_hash, status, department, clearance_level)
                VALUES (?, ?, ?, 'ACTIVE', 'Finance', 3)
                """, userId, email, encoder.encode(PASSWORD));
        jdbc.update("INSERT INTO iam.roles (id, name) VALUES (?, ?)", roleId,
                "TEST_" + roleId.toString().replace("-", "").toUpperCase(Locale.ROOT));
        for (String permission : List.of("RESOURCE:READ", "RESOURCE:WRITE")) {
            jdbc.update("INSERT INTO iam.permissions (id, name) VALUES (?, ?) ON CONFLICT (name) DO NOTHING",
                    UUID.randomUUID(), permission);
            jdbc.update("""
                    INSERT INTO iam.role_permissions (role_id, permission_id)
                    SELECT ?, id FROM iam.permissions WHERE name = ?
                    """, roleId, permission);
        }
        jdbc.update("INSERT INTO iam.user_roles (user_id, role_id) VALUES (?, ?)", userId, roleId);
        jdbc.update("""
                INSERT INTO iam.secured_resources (id, owner_id, department, classification, content)
                VALUES (?, ?, 'Finance', 2, ?)
                """, resourceId, userId, ORIGINAL_CONTENT);
    }

    @AfterEach
    void cleanup() {
        // Audit rows are deliberately retained: even test cleanup must not mutate the ledger.
        jdbc.update("DELETE FROM iam.secured_resources WHERE id = ?", resourceId);
        jdbc.update("DELETE FROM iam.users WHERE id = ?", userId);
        jdbc.update("DELETE FROM iam.role_permissions WHERE role_id = ?", roleId);
        jdbc.update("DELETE FROM iam.roles WHERE id = ?", roleId);
        jdbc.update("""
                DELETE FROM iam.permissions p WHERE p.name IN ('RESOURCE:READ', 'RESOURCE:WRITE')
                AND NOT EXISTS (SELECT 1 FROM iam.role_permissions rp WHERE rp.permission_id = p.id)
                """);
    }

    @Test
    void productionHttpFlowEnforcesRbacAbacAndVersioningWithRedactedDurableAudit() throws Exception {
        Tokens tokens = login();
        MvcResult read = noStore(mvc.perform(resourceRequest(tokens.accessToken())
                        .queryParam("trace", "private-query-token"))).andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(resourceId.toString()))
                .andExpect(jsonPath("$.ownerId").value(userId.toString()))
                .andExpect(jsonPath("$.content").value(ORIGINAL_CONTENT))
                .andExpect(jsonPath("$.version").value(0)).andReturn();
        assertThat(fields(mapper.readTree(read.getResponse().getContentAsString())))
                .containsExactlyInAnyOrder("id", "ownerId", "department", "classification", "content", "version");

        String updatedContent = "updated sensitive content";
        noStore(mvc.perform(writeRequest(tokens.accessToken(), updatedContent, 0)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.content").value(updatedContent))
                .andExpect(jsonPath("$.version").value(1));
        problem(mvc.perform(writeRequest(tokens.accessToken(), "must never replace content", 0)), 409)
                .andExpect(header().doesNotExist(HttpHeaders.RETRY_AFTER));
        assertThat(storedContent()).isEqualTo(updatedContent);

        jdbc.update("""
                DELETE FROM iam.role_permissions WHERE role_id = ?
                AND permission_id = (SELECT id FROM iam.permissions WHERE name = 'RESOURCE:WRITE')
                """, roleId);
        problem(mvc.perform(writeRequest(tokens.accessToken(), "revoked permission write", 1)), 403);
        jdbc.update("UPDATE iam.secured_resources SET classification = 4 WHERE id = ?", resourceId);
        problem(mvc.perform(resourceRequest(tokens.accessToken())), 403);
        jdbc.update("UPDATE iam.secured_resources SET classification = 2 WHERE id = ?", resourceId);
        problem(mvc.perform(resourceRequest(tokens.accessToken()).header("X-Forwarded-For", "10.20.1.7")
                .with(request -> { request.setRemoteAddr("203.0.113.9"); return request; })), 403);

        List<JsonNode> events = auditEvents();
        assertThat(events).hasSize(14);
        assertCompleteAuditPairs(events);
        assertThat(outcomes(events, "AUTH_LOGIN", "SUCCEEDED")).hasSize(1)
                .allSatisfy(event -> assertThat(event.path("actorId").asText()).isEqualTo("anonymous"));
        assertThat(outcomes(events, "RESOURCE_READ", "SUCCEEDED")).hasSize(1);
        assertThat(outcomes(events, "RESOURCE_READ", "FAILED")).hasSize(2)
                .allSatisfy(event -> assertThat(event.path("outcomeType").asText()).isEqualTo("ACCESS_DENIED"));
        assertThat(outcomes(events, "RESOURCE_WRITE", "SUCCEEDED")).hasSize(1);
        assertThat(outcomes(events, "RESOURCE_WRITE", "FAILED")).hasSize(2);
        events.stream().filter(event -> event.path("action").asText().startsWith("RESOURCE_"))
                .forEach(event -> {
                    assertThat(event.path("actorId").asText()).isEqualTo(userId.toString());
                    assertThat(event.path("arguments").path("arg0").asText()).isEqualTo(resourceId.toString());
                    assertThat(event.path("requestPath").asText()).isEqualTo("/api/v1/resources/" + resourceId);
                });
        assertRedacted(events, PASSWORD, email, ORIGINAL_CONTENT, updatedContent,
                "private-query-token", "must never replace content", "revoked permission write",
                tokens.accessToken(), tokens.refreshToken());

        jdbc.update("UPDATE iam.users SET status = 'DISABLED' WHERE id = ?", userId);
        problem(mvc.perform(resourceRequest(tokens.accessToken())), 401)
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
        assertThat(auditEvents()).hasSize(events.size()); // Rejected before the audited service boundary.
    }

    @Test
    void httpRefreshReplayRevokesTheFamilyAndAuditsTheFailedAttemptWithoutTokens() throws Exception {
        Tokens original = login();
        Tokens rotated = refresh(original.refreshToken());
        assertThat(rotated.accessToken()).isNotEqualTo(original.accessToken());
        assertThat(rotated.refreshToken()).isNotEqualTo(original.refreshToken());
        noStore(mvc.perform(resourceRequest(rotated.accessToken()))).andExpect(status().isOk());
        problem(mvc.perform(refreshRequest(original.refreshToken())), 401);
        problem(mvc.perform(resourceRequest(rotated.accessToken())), 401);
        problem(mvc.perform(resourceRequest(original.accessToken())), 401);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iam.auth_sessions WHERE user_id = ? AND revoked_at IS NULL",
                Integer.class, userId)).isZero();
        List<JsonNode> events = auditEvents();
        assertCompleteAuditPairs(events);
        assertThat(outcomes(events, "AUTH_REFRESH", "SUCCEEDED")).hasSize(1);
        assertThat(outcomes(events, "AUTH_REFRESH", "FAILED")).hasSize(1)
                .allSatisfy(event -> assertThat(event.path("outcomeType").asText()).isEqualTo("AUTHENTICATION_FAILED"));
        assertRedacted(events, original.accessToken(), original.refreshToken(),
                rotated.accessToken(), rotated.refreshToken(), PASSWORD, email, ORIGINAL_CONTENT);
    }

    @Test
    void httpLogoutRevokesEveryAccessTokenInTheSessionAndTheCurrentJti() throws Exception {
        Tokens original = login();
        Tokens rotated = refresh(original.refreshToken());
        Jwt current = decoder.decode(rotated.accessToken());
        noStore(mvc.perform(request(post("/api/v1/auth/logout"))
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + rotated.accessToken())))
                .andExpect(status().isNoContent()).andExpect(content().string(""));
        verify(blacklist).revoke(UUID.fromString(current.getId()), current.getExpiresAt());
        problem(mvc.perform(resourceRequest(original.accessToken())), 401);
        problem(mvc.perform(resourceRequest(rotated.accessToken())), 401);
        problem(mvc.perform(refreshRequest(rotated.refreshToken())), 401);
        List<JsonNode> events = auditEvents();
        assertCompleteAuditPairs(events);
        assertThat(outcomes(events, "AUTH_LOGOUT", "SUCCEEDED")).hasSize(1).allSatisfy(event -> {
            assertThat(event.path("actorId").asText()).isEqualTo(userId.toString());
            assertThat(event.path("arguments").path("arg0").asText()).isEqualTo("[REDACTED]");
        });
        assertRedacted(events, original.accessToken(), original.refreshToken(),
                rotated.accessToken(), rotated.refreshToken(), PASSWORD, email);
    }

    @Test
    void invalidCredentialsProduceStandardProblemAndAnAnonymousFailedAudit() throws Exception {
        String wrongPassword = "wrong-private-password";
        problem(mvc.perform(request(post("/api/v1/auth/login")).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsBytes(Map.of("email", email, "password", wrongPassword)))), 401);
        List<JsonNode> events = auditEvents();
        assertThat(events).hasSize(2);
        assertCompleteAuditPairs(events);
        assertThat(outcomes(events, "AUTH_LOGIN", "FAILED")).hasSize(1).allSatisfy(event -> {
            assertThat(event.path("actorId").asText()).isEqualTo("anonymous");
            assertThat(event.path("outcomeType").asText()).isEqualTo("AUTHENTICATION_FAILED");
        });
        assertRedacted(events, email, wrongPassword, PASSWORD);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iam.auth_sessions WHERE user_id = ?",
                Integer.class, userId)).isZero();
    }

    @Test
    void strictDtosRejectUnknownAttributesAndInvalidValuesBeforeAuditedServiceInvocation() throws Exception {
        problem(mvc.perform(request(post("/api/v1/auth/login")).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsBytes(Map.of("email", email, "password", PASSWORD, "roles", List.of("ADMIN"))))), 400);
        problem(mvc.perform(request(post("/api/v1/auth/refresh")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"too-short-secret\"}")), 400);
        assertThat(auditEvents()).isEmpty();
        Tokens tokens = login();
        problem(mvc.perform(request(put("/api/v1/resources/" + resourceId))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.accessToken())
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(Map.of(
                        "content", "forbidden attribute write", "expectedVersion", 0,
                        "ownerId", UUID.randomUUID().toString(), "classification", 0)))), 400);
        problem(mvc.perform(request(put("/api/v1/resources/" + resourceId))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.accessToken())
                .contentType(MediaType.APPLICATION_JSON).content("{\"content\":\"missing-version-private-content\"}")), 400);
        problem(mvc.perform(writeRequest(tokens.accessToken(), "negative-version-private-content", -1)), 400);
        assertThat(storedContent()).isEqualTo(ORIGINAL_CONTENT);
        assertThat(auditEvents()).hasSize(2); // Only the successful login reached a service boundary.
    }

    @Test
    void actualCommitFailureRollsBackResourceAndSuccessAuditThenAppendsDurableFailure() throws Exception {
        Tokens tokens = login();
        // A deferred constraint fails after the method returned and its success event was inserted,
        // exercising the actual JPA transaction's afterCompletion path through production HTTP.
        String triggerName = "security_it_reject_" + resourceId.toString().replace("-", "");
        jdbc.execute("""
                CREATE FUNCTION iam.%s() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.id = '%s'::uuid THEN
                        RAISE EXCEPTION 'Forced integration rollback' USING ERRCODE = '23514';
                    END IF;
                    RETURN NEW;
                END;
                $$
                """.formatted(triggerName, resourceId));
        try {
            jdbc.execute("""
                    CREATE CONSTRAINT TRIGGER %s AFTER UPDATE ON iam.secured_resources
                    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.%s()
                    """.formatted(triggerName, triggerName));
            problem(mvc.perform(writeRequest(tokens.accessToken(), "rolled-back-secret-content", 0)), 503);
            assertThat(storedContent()).isEqualTo(ORIGINAL_CONTENT);
            assertThat(jdbc.queryForObject("SELECT version FROM iam.secured_resources WHERE id = ?",
                    Long.class, resourceId)).isZero();
            List<JsonNode> events = auditEvents();
            assertCompleteAuditPairs(events);
            assertThat(outcomes(events, "RESOURCE_WRITE", "STARTED")).hasSize(1);
            assertThat(outcomes(events, "RESOURCE_WRITE", "SUCCEEDED")).isEmpty();
            assertThat(outcomes(events, "RESOURCE_WRITE", "FAILED")).hasSize(1)
                    .allSatisfy(event -> assertThat(event.path("outcomeType").asText())
                            .isIn("TRANSACTION_ROLLED_BACK", "TRANSACTION_OUTCOME_UNKNOWN"));
            assertRedacted(events, "rolled-back-secret-content", ORIGINAL_CONTENT,
                    tokens.accessToken(), tokens.refreshToken(), PASSWORD, email);
            assertThat(jdbc.queryForObject("""
                    SELECT count(*) FROM iam.audit_delivery d JOIN iam.audit_events e ON e.id = d.event_id
                    WHERE e.payload ->> 'userAgent' = ?
                    """, Integer.class, auditMarker)).isEqualTo(events.size());
        } finally {
            jdbc.execute("DROP TRIGGER IF EXISTS " + triggerName + " ON iam.secured_resources");
            jdbc.execute("DROP FUNCTION iam." + triggerName + "()");
        }
    }

    private Tokens login() throws Exception {
        return tokenResponse(mvc.perform(request(post("/api/v1/auth/login"))
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(
                        Map.of("email", email.toUpperCase(Locale.ROOT), "password", PASSWORD)))));
    }

    private Tokens refresh(String token) throws Exception {
        return tokenResponse(mvc.perform(refreshRequest(token)));
    }

    private MockHttpServletRequestBuilder refreshRequest(String token) throws Exception {
        return request(post("/api/v1/auth/refresh")).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsBytes(Map.of("refreshToken", token)));
    }

    private Tokens tokenResponse(ResultActions response) throws Exception {
        MvcResult result = noStore(response).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.tokenType").value("Bearer")).andReturn();
        assertThat(result.getRequest().getSession(false)).isNull();
        JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
        assertThat(fields(json)).containsExactlyInAnyOrder("tokenType", "accessToken", "refreshToken",
                "accessTokenExpiresAt", "refreshTokenExpiresAt");
        assertThat(Instant.parse(json.path("accessTokenExpiresAt").asText())).isAfter(JwtTestSupport.NOW);
        assertThat(Instant.parse(json.path("refreshTokenExpiresAt").asText())).isAfter(JwtTestSupport.NOW);
        assertThat(json.path("refreshToken").asText()).matches("[A-Za-z0-9_-]{43}");
        Jwt jwt = decoder.decode(json.path("accessToken").asText());
        assertThat(jwt.getSubject()).isEqualTo(userId.toString());
        return new Tokens(json.path("accessToken").asText(), json.path("refreshToken").asText());
    }

    private MockHttpServletRequestBuilder resourceRequest(String token) {
        return request(get("/api/v1/resources/" + resourceId))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }

    private MockHttpServletRequestBuilder writeRequest(String token, String content, long version) throws Exception {
        return request(put("/api/v1/resources/" + resourceId))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsBytes(Map.of("content", content, "expectedVersion", version)));
    }

    private MockHttpServletRequestBuilder request(MockHttpServletRequestBuilder request) {
        return request.header(HttpHeaders.USER_AGENT, auditMarker)
                .with(servlet -> { servlet.setRemoteAddr("10.20.1.7"); return servlet; });
    }

    private ResultActions noStore(ResultActions response) throws Exception {
        return response.andExpect(header().string(HttpHeaders.CACHE_CONTROL, Matchers.containsString("no-store")))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
    }

    private ResultActions problem(ResultActions response, int expectedStatus) throws Exception {
        return noStore(response).andExpect(status().is(expectedStatus))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value("about:blank"))
                .andExpect(jsonPath("$.status").value(expectedStatus))
                .andExpect(jsonPath("$.title").isString()).andExpect(jsonPath("$.detail").isString())
                .andExpect(jsonPath("$.stackTrace").doesNotExist())
                .andExpect(jsonPath("$.exception").doesNotExist());
    }

    private String storedContent() {
        return jdbc.queryForObject("SELECT content FROM iam.secured_resources WHERE id = ?", String.class, resourceId);
    }

    private List<JsonNode> auditEvents() throws Exception {
        List<JsonNode> events = new ArrayList<>();
        for (String payload : jdbc.queryForList("""
                SELECT payload::text FROM iam.audit_events WHERE payload ->> 'userAgent' = ?
                ORDER BY created_at, id
                """, String.class, auditMarker)) {
            events.add(mapper.readTree(payload));
        }
        return events;
    }

    private static void assertCompleteAuditPairs(List<JsonNode> events) {
        assertThat(events).isNotEmpty();
        Map<String, List<JsonNode>> invocations = events.stream()
                .collect(Collectors.groupingBy(event -> event.path("invocationId").asText()));
        invocations.values().forEach(pair -> {
            assertThat(pair).hasSize(2);
            assertThat(pair.stream().map(event -> event.path("id").asText()).distinct().count()).isEqualTo(2);
            assertThat(pair.stream().filter(event -> event.path("phase").asText().equals("STARTED")).count()).isOne();
            assertThat(pair.stream().filter(event -> Set.of("SUCCEEDED", "FAILED")
                    .contains(event.path("phase").asText())).count()).isOne();
        });
    }

    private static List<JsonNode> outcomes(List<JsonNode> events, String action, String phase) {
        return events.stream().filter(event -> event.path("action").asText().equals(action)
                && event.path("phase").asText().equals(phase)).toList();
    }

    private static void assertRedacted(List<JsonNode> events, String... secrets) {
        events.forEach(event -> {
            for (String secret : secrets) {
                assertThat(event.toString().toLowerCase(Locale.ROOT))
                        .doesNotContain(secret.toLowerCase(Locale.ROOT));
            }
        });
    }

    private static Set<String> fields(JsonNode node) {
        Set<String> fields = new HashSet<>();
        node.fieldNames().forEachRemaining(fields::add);
        return fields;
    }

    private record Tokens(String accessToken, String refreshToken) {
        @Override public String toString() { return "Tokens[REDACTED]"; }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class FixedClock {
        @Bean @Primary Clock integrationClock() { return JwtTestSupport.CLOCK; }
    }
}
