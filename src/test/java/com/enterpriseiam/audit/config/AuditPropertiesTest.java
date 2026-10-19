package com.enterpriseiam.audit.config;

import java.time.Duration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AuditPropertiesTest {
    @Test
    void boundedDefaultsEnableDelivery() {
        AuditProperties value = new AuditProperties(null, null, null, null, null, null, null, null, null);
        assertTrue(value.dispatcherEnabled());
        assertEquals(50, value.batchSize());
        assertEquals(Duration.ofSeconds(5), value.pollInterval());
    }

    @Test
    void rejectsAnUnboundedExecutorAndNegativeDuration() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuditProperties(null, null, null, null, null, null, null, 100, null));
        assertThrows(IllegalArgumentException.class,
                () -> new AuditProperties(null, null, null, null, null, null, null, null, 0));
        assertThrows(IllegalArgumentException.class,
                () -> new AuditProperties(null, Duration.ofSeconds(-1), null, null, null, null, null, null, null));
    }

    @Test
    void rejectsMaximumDelaySmallerThanBaseDelay() {
        assertThrows(IllegalArgumentException.class, () -> new AuditProperties(null, null, null, null,
                Duration.ofMinutes(1), Duration.ofSeconds(10), null, null, null));
    }
}
