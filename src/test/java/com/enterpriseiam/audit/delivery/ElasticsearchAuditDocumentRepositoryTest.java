package com.enterpriseiam.audit.delivery;

import co.elastic.clients.elasticsearch._types.ElasticsearchException;
import co.elastic.clients.elasticsearch._types.ErrorResponse;
import com.enterpriseiam.audit.model.AuditEvent;
import com.enterpriseiam.audit.model.AuditPhase;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import org.apache.http.HttpVersion;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.message.BasicStatusLine;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.ResponseException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.elasticsearch.UncategorizedElasticsearchException;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.convert.MappingElasticsearchConverter;
import org.springframework.data.elasticsearch.core.document.Document;
import org.springframework.data.elasticsearch.core.mapping.IndexCoordinates;
import org.springframework.data.elasticsearch.core.mapping.SimpleElasticsearchMappingContext;
import org.springframework.data.elasticsearch.core.query.IndexQuery;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ElasticsearchAuditDocumentRepositoryTest {
    private final ElasticsearchOperations operations = mock(ElasticsearchOperations.class);
    private final ElasticsearchAuditDocumentRepository repository = new ElasticsearchAuditDocumentRepository(operations);

    @Test
    void createsOnlyWithStableUuidAndEventTimeUtcConcreteIndex() {
        AuditDocument document = document();
        assertEquals(AuditDocumentRepository.CreateResult.CREATED, repository.createOnly(document));
        ArgumentCaptor<IndexQuery> query = ArgumentCaptor.forClass(IndexQuery.class);
        ArgumentCaptor<IndexCoordinates> index = ArgumentCaptor.forClass(IndexCoordinates.class);
        verify(operations).index(query.capture(), index.capture());
        assertEquals(IndexQuery.OpType.CREATE, query.getValue().getOpType());
        assertEquals(document.id(), query.getValue().getId());
        assertSame(document, query.getValue().getObject());
        assertEquals("enterpriseiam-audit-2026.10.23", index.getValue().getIndexName());
        verifyNoMoreInteractions(operations);
    }

    @Test
    void aVerifiedNativeCreateConflictIsIdempotent() {
        ElasticsearchException conflict = new ElasticsearchException("index", ErrorResponse.of(builder -> builder
                .status(409).error(error -> error.type("version_conflict_engine_exception").reason("exists"))));
        when(operations.index(any(), any())).thenThrow(conflict);
        assertEquals(AuditDocumentRepository.CreateResult.ALREADY_PRESENT, repository.createOnly(document()));
    }

    @Test
    void translated409IsIdempotentButOtherStatusCodesPropagateForRetry() {
        ElasticsearchException nativeConflict = new ElasticsearchException("index", ErrorResponse.of(builder -> builder
                .status(409).error(error -> error.type("version_conflict_engine_exception").reason("exists"))));
        when(operations.index(any(), any())).thenThrow(
                new UncategorizedElasticsearchException("conflict", 409, "", nativeConflict));
        assertEquals(AuditDocumentRepository.CreateResult.ALREADY_PRESENT, repository.createOnly(document()));
        for (int status : new int[]{400, 401, 403, 404, 429, 500, 503}) {
            RuntimeException failure = new UncategorizedElasticsearchException("failure", status, "", null);
            doThrow(failure).when(operations).index(any(), any());
            assertSame(failure, assertThrows(RuntimeException.class, () -> repository.createOnly(document())));
        }
    }

    @Test
    void anUnclassifiedFailureIsNeverMistakenForAnAlreadyStoredEvent() {
        RuntimeException failure = new IllegalStateException("409 in a message is not a verified conflict");
        when(operations.index(any(), any())).thenThrow(failure);
        assertSame(failure, assertThrows(RuntimeException.class, () -> repository.createOnly(document())));
        RuntimeException unverified409 = new UncategorizedElasticsearchException("unknown conflict", 409, "", null);
        doThrow(unverified409).when(operations).index(any(), any());
        assertSame(unverified409, assertThrows(RuntimeException.class, () -> repository.createOnly(document())));
    }

    @Test
    void actualLowLevelResponseWrappedBySpringDataIsAnIdempotentDuplicate() {
        RuntimeException wrapped = lowLevelFailure(409,
                "{\"error\":{\"type\":\"version_conflict_engine_exception\",\"reason\":\"already exists\"},\"status\":409}");
        doThrow(wrapped).when(operations).index(any(), any());
        assertEquals(AuditDocumentRepository.CreateResult.ALREADY_PRESENT, repository.createOnly(document()));
    }

    @Test
    void lowLevelConflictNeedsVerifiedStatusAndErrorTypeAndBoundedValidJson() {
        for (String body : new String[]{
                "{\"error\":{\"type\":\"other_conflict\"},\"status\":409}",
                "version_conflict_engine_exception",
                "{\"error\":{\"type\":\"version_conflict_engine_exception\"}}{}",
                "{\"error\":{\"type\":\"version_conflict_engine_exception\",\"reason\":\"" + "x".repeat(16_384) + "\"}}",
                "[".repeat(20) + "0" + "]".repeat(20)}) {
            RuntimeException failure = lowLevelFailure(409, body);
            doThrow(failure).when(operations).index(any(), any());
            assertSame(failure, assertThrows(RuntimeException.class, () -> repository.createOnly(document())));
        }
        RuntimeException forbidden = lowLevelFailure(403,
                "{\"error\":{\"type\":\"version_conflict_engine_exception\"},\"status\":403}");
        doThrow(forbidden).when(operations).index(any(), any());
        assertSame(forbidden, assertThrows(RuntimeException.class, () -> repository.createOnly(document())));
    }

    @Test
    void converterWritesOnlyDeclaredFieldsWithoutClassMetadata() {
        MappingElasticsearchConverter converter = new MappingElasticsearchConverter(new SimpleElasticsearchMappingContext());
        converter.afterPropertiesSet();
        Document target = Document.create();
        converter.write(document(), target);
        assertFalse(target.containsKey("_class"));
        assertEquals(13, target.size());
        assertEquals("SUCCEEDED", target.get("phase"));
        assertEquals(Map.of("resourceId", "safe-id"), target.get("arguments"));
        assertTrue(target.get("occurredAt").toString().startsWith("2026-10-23T23:59:59"));
    }

    static AuditDocument document() {
        return AuditDocument.from(new AuditEvent(UUID.randomUUID(), UUID.randomUUID(),
                Instant.parse("2026-10-23T23:59:59.123456Z"), "RESOURCE_READ", AuditPhase.SUCCEEDED,
                UUID.randomUUID().toString(), "ResourceService.read", Map.of("resourceId", "safe-id"),
                "127.0.0.1", "test", "GET", "/api/v1/resources/{id}", "SUCCESS"));
    }

    private static RuntimeException lowLevelFailure(int status, String body) {
        Response response = mock(Response.class);
        when(response.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, status, "test"));
        when(response.getEntity()).thenReturn(new ByteArrayEntity(body.getBytes(StandardCharsets.UTF_8)));
        ResponseException lowLevel = mock(ResponseException.class);
        when(lowLevel.getResponse()).thenReturn(response);
        return new DataAccessResourceFailureException("HTTP failure", new RuntimeException(lowLevel));
    }
}
