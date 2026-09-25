package com.enterpriseiam.audit.delivery;

import com.enterpriseiam.audit.model.AuditEvent;
import java.time.Instant;
import java.util.Map;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.DateFormat;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Dynamic;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;
import org.springframework.data.elasticsearch.annotations.WriteTypeHint;

@Document(indexName = "enterpriseiam-audit", createIndex = false,
        writeTypeHint = WriteTypeHint.FALSE, dynamic = Dynamic.STRICT)
public record AuditDocument(
        @Id @Field(type = FieldType.Keyword) String id,
        @Field(type = FieldType.Keyword) String invocationId,
        @Field(type = FieldType.Date, format = DateFormat.date_optional_time) Instant occurredAt,
        @Field(type = FieldType.Keyword) String action,
        @Field(type = FieldType.Keyword) String phase,
        @Field(type = FieldType.Keyword) String actorId,
        @Field(type = FieldType.Keyword) String method,
        @Field(type = FieldType.Object, enabled = false) Map<String, String> arguments,
        @Field(type = FieldType.Keyword) String remoteAddress,
        @Field(type = FieldType.Keyword, index = false) String userAgent,
        @Field(type = FieldType.Keyword) String requestMethod,
        @Field(type = FieldType.Keyword) String requestPath,
        @Field(type = FieldType.Keyword) String outcomeType) {
    public AuditDocument {
        arguments = Map.copyOf(arguments);
    }

    public static AuditDocument from(AuditEvent event) {
        return new AuditDocument(event.id().toString(), event.invocationId().toString(), event.occurredAt(),
                event.action(), event.phase().name(), event.actorId(), event.method(), event.arguments(),
                event.remoteAddress(), event.userAgent(), event.requestMethod(), event.requestPath(), event.outcomeType());
    }

    @Override
    public String toString() {
        return "AuditDocument[id=" + id + ", phase=" + phase + "]";
    }
}
