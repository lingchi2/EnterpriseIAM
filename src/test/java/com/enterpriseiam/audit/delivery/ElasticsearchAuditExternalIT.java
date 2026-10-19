package com.enterpriseiam.audit.delivery;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.json.jackson.JacksonJsonpMapper;
import co.elastic.clients.transport.rest_client.RestClientTransport;
import com.enterpriseiam.audit.model.AuditEvent;
import com.enterpriseiam.audit.model.AuditPhase;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.UUID;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.client.RestClient;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.data.elasticsearch.client.elc.ElasticsearchTemplate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Explicit external-services profile only; never silently skipped. Requires an isolated,
 * security-enabled Elasticsearch 8.13.4 instance and administrative test credentials.
 * Creates a test role/user, preprovisions the current UTC day index, and retains test documents.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ElasticsearchAuditExternalIT {
    private final ObjectMapper mapper = new ObjectMapper();
    private final String identity = "enterpriseiam_audit_test_" + UUID.randomUUID().toString().replace("-", "");
    private final String writerPassword = UUID.randomUUID().toString();
    private final Instant eventTime = Instant.now();
    private final String index = "enterpriseiam-audit-"
            + DateTimeFormatter.ofPattern("uuuu.MM.dd").withZone(ZoneOffset.UTC).format(eventTime);
    private RestClient admin;
    private RestClient writer;
    private RestClientTransport transport;
    private AuditDocumentRepository repository;

    @BeforeAll
    void provisionRestrictedWriterAndConcreteIndex() throws Exception {
        String endpoint = environment("IAM_TEST_ELASTICSEARCH_URL");
        admin = client(endpoint, environment("IAM_TEST_ELASTICSEARCH_USERNAME"),
                environment("IAM_TEST_ELASTICSEARCH_PASSWORD"));
        perform(admin, "PUT", "/_security/role/" + identity,
                Files.readString(Path.of("ops/elasticsearch/audit-writer-role.json")));
        perform(admin, "PUT", "/_security/user/" + identity,
                mapper.writeValueAsString(Map.of("password", writerPassword, "roles", new String[]{identity})));
        // RestClient deliberately returns HEAD 404 responses rather than throwing.
        int indexStatus = admin.performRequest(new Request("HEAD", "/" + index)).getStatusLine().getStatusCode();
        if (indexStatus == 404) {
            var definition = mapper.readTree(Files.readString(Path.of("ops/elasticsearch/audit-index-template.json")))
                    .get("template");
            perform(admin, "PUT", "/" + index, mapper.writeValueAsString(definition));
        }
        assertEquals(200, admin.performRequest(new Request("HEAD", "/" + index)).getStatusLine().getStatusCode(),
                "The operator must preprovision the audit index before the restricted writer is used");
        writer = client(endpoint, identity, writerPassword);
        transport = new RestClientTransport(writer, new JacksonJsonpMapper());
        repository = new ElasticsearchAuditDocumentRepository(new ElasticsearchTemplate(new ElasticsearchClient(transport)));
    }

    @AfterAll
    void closeAndRemoveTestPrincipals() throws Exception {
        try {
            if (transport != null) {
                transport.close();
            } else if (writer != null) {
                writer.close();
            }
        } finally {
            if (admin != null) {
                try {
                    perform(admin, "DELETE", "/_security/user/" + identity, null);
                    perform(admin, "DELETE", "/_security/role/" + identity, null);
                } finally {
                    admin.close();
                }
            }
        }
    }

    @Test
    void actualSpringDataCreateIsIdempotentAndTheStoredPayloadRemainsUnchanged() throws Exception {
        AuditDocument original = document("RESOURCE_READ");
        assertEquals(AuditDocumentRepository.CreateResult.CREATED, repository.createOnly(original));
        assertEquals(AuditDocumentRepository.CreateResult.ALREADY_PRESENT, repository.createOnly(original));
        Request lookup = new Request("GET", "/" + index + "/_doc/" + original.id());
        var stored = mapper.readTree(admin.performRequest(lookup).getEntity().getContent()).get("_source");
        assertEquals(original.action(), stored.get("action").asText());
        assertEquals(original.id(), stored.get("id").asText());
        assertFalse(stored.has("_class"));
        assertEquals(original.arguments().get("resourceId"), stored.get("arguments").get("resourceId").asText());
    }

    @Test
    void restrictedPrincipalCannotOverwriteDeleteOrCreateAnUnprovisionedIndex() throws Exception {
        AuditDocument original = document("RESOURCE_WRITE");
        assertEquals(AuditDocumentRepository.CreateResult.CREATED, repository.createOnly(original));
        denied(() -> perform(writer, "PUT", "/" + index + "/_doc/" + original.id(), "{\"action\":\"TAMPERED\"}"));
        denied(() -> perform(writer, "DELETE", "/" + index + "/_doc/" + original.id(), null));
        denied(() -> perform(writer, "PUT", "/enterpriseiam-audit-unprovisioned-" + identity
                + "/_create/" + UUID.randomUUID(), "{\"action\":\"UNPROVISIONED\"}"));
        Request lookup = new Request("GET", "/" + index + "/_doc/" + original.id());
        var stored = mapper.readTree(admin.performRequest(lookup).getEntity().getContent()).get("_source");
        assertEquals("RESOURCE_WRITE", stored.get("action").asText());
    }

    private AuditDocument document(String action) {
        return AuditDocument.from(new AuditEvent(UUID.randomUUID(), UUID.randomUUID(), eventTime, action,
                AuditPhase.SUCCEEDED, UUID.randomUUID().toString(), "ExternalAuditTest.operation",
                Map.of("resourceId", UUID.randomUUID().toString()), "127.0.0.1", "test", "POST",
                "/api/v1/resources/{id}", "SUCCESS"));
    }

    private static RestClient client(String endpoint, String username, String password) {
        BasicCredentialsProvider credentials = new BasicCredentialsProvider();
        credentials.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));
        return RestClient.builder(HttpHost.create(endpoint))
                .setHttpClientConfigCallback(http -> http.setDefaultCredentialsProvider(credentials))
                .setRequestConfigCallback(request -> request.setConnectTimeout(2_000).setSocketTimeout(5_000)).build();
    }

    private static void perform(RestClient client, String method, String path, String body) throws Exception {
        Request request = new Request(method, path);
        if (body != null) {
            request.setJsonEntity(body);
        }
        client.performRequest(request);
    }

    private static void denied(org.junit.jupiter.api.function.Executable operation) {
        ResponseException failure = assertThrows(ResponseException.class, operation);
        assertEquals(403, failure.getResponse().getStatusLine().getStatusCode());
    }

    private static String environment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for the explicit external-services test profile");
        }
        return value;
    }
}
