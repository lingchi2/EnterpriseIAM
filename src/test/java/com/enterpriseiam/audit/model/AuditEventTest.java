package com.enterpriseiam.audit.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuditEventTest {
    @Test
    void eventDefensivelyCopiesTheArgumentMapAndDoesNotExposeItForMutation() {
        Map<String, String> values = new LinkedHashMap<>(Map.of("arg0", "10"));
        AuditEvent event = event("RESOURCE_READ", "anonymous", values, "/resource", "RETURNED");
        values.put("arg0", "20");
        assertThat(event.arguments()).containsEntry("arg0", "10");
        assertThatThrownBy(() -> event.arguments().put("arg1", "30"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejectsUnboundedOrControlContainingMetadata() {
        assertThatThrownBy(() -> event("RESOURCE_READ", "anonymous", Map.of(), "x".repeat(1025), "RETURNED"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> event("RESOURCE_READ", "anonymous", Map.of(), "/path\r\n", "RETURNED"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> event("RESOURCE_READ", "anonymous", Map.of("arg0", "x".repeat(129)), "/", "RETURNED"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesFreeTextActionsOutcomesAndUnverifiedActorNames() {
        assertThatThrownBy(() -> event("user-entered action", "anonymous", Map.of(), "/", "RETURNED"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> event("RESOURCE_READ", "anonymous", Map.of(), "/", "Password was secret"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> event("RESOURCE_READ", "user@example.com", Map.of(), "/", "RETURNED"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesOversizedArgumentMaps() {
        Map<String, String> arguments = new LinkedHashMap<>();
        for (int index = 0; index <= AuditEvent.MAX_ARGUMENTS; index++) arguments.put("arg" + index, "1");
        assertThatThrownBy(() -> event("RESOURCE_READ", "anonymous", arguments, "/", "RETURNED"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static AuditEvent event(String action, String actor, Map<String, String> arguments,
            String path, String outcome) {
        return new AuditEvent(UUID.randomUUID(), UUID.randomUUID(), Instant.now(), action,
                AuditPhase.SUCCEEDED, actor, "example.Service.read", arguments, "127.0.0.1", "agent",
                "GET", path, outcome);
    }
}
