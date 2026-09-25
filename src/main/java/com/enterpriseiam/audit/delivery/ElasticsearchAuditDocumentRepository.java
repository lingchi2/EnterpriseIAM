package com.enterpriseiam.audit.delivery;

import co.elastic.clients.elasticsearch._types.ElasticsearchException;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import org.apache.http.HttpEntity;
import org.elasticsearch.client.ResponseException;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.mapping.IndexCoordinates;
import org.springframework.data.elasticsearch.core.query.IndexQuery;
import org.springframework.data.elasticsearch.core.query.IndexQueryBuilder;
import org.springframework.stereotype.Repository;

@Repository
public class ElasticsearchAuditDocumentRepository implements AuditDocumentRepository {
    private static final DateTimeFormatter INDEX_DAY = DateTimeFormatter.ofPattern("uuuu.MM.dd")
            .withZone(ZoneOffset.UTC);
    private static final int MAX_CONFLICT_BODY_BYTES = 16_384;
    private static final ObjectMapper CONFLICT_BODY = new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(16)
                    .maxStringLength(MAX_CONFLICT_BODY_BYTES).maxNumberLength(32).build()).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final ElasticsearchOperations operations;

    public ElasticsearchAuditDocumentRepository(ElasticsearchOperations operations) {
        this.operations = operations;
    }

    @Override
    public CreateResult createOnly(AuditDocument document) {
        IndexQuery query = new IndexQueryBuilder().withId(document.id()).withObject(document)
                .withOpType(IndexQuery.OpType.CREATE).build();
        // Event-time concrete indices keep retries on the same index across midnight.
        IndexCoordinates index = IndexCoordinates.of("enterpriseiam-audit-" + INDEX_DAY.format(document.occurredAt()));
        try {
            operations.index(query, index);
            return CreateResult.CREATED;
        } catch (RuntimeException failure) {
            if (isConflict(failure)) {
                return CreateResult.ALREADY_PRESENT;
            }
            throw failure;
        }
    }

    private static boolean isConflict(Throwable failure) {
        Throwable current = failure;
        for (int depth = 0; current != null && depth < 16; depth++, current = current.getCause()) {
            if (current instanceof ElasticsearchException elastic
                    && elastic.status() == 409
                    && "version_conflict_engine_exception".equals(elastic.error().type())) {
                return true;
            }
            if (current instanceof ResponseException response && isLowLevelConflict(response)) {
                return true;
            }
        }
        return false;
    }

    /** Spring Data may wrap a low-level HTTP failure without a typed ElasticsearchException. */
    private static boolean isLowLevelConflict(ResponseException failure) {
        if (failure.getResponse().getStatusLine().getStatusCode() != 409) {
            return false;
        }
        HttpEntity entity = failure.getResponse().getEntity();
        if (entity == null || entity.getContentLength() > MAX_CONFLICT_BODY_BYTES) {
            return false;
        }
        try (InputStream content = entity.getContent()) {
            byte[] body = content.readNBytes(MAX_CONFLICT_BODY_BYTES + 1);
            if (body.length > MAX_CONFLICT_BODY_BYTES) {
                return false;
            }
            JsonNode json = CONFLICT_BODY.readTree(body);
            return json != null && "version_conflict_engine_exception".equals(json.path("error").path("type").asText());
        } catch (IOException | RuntimeException unreadableResponse) {
            // Unverifiable responses must retry. Never log bodies or exception messages.
            return false;
        }
    }
}
