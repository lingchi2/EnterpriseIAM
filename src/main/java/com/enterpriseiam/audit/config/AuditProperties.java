package com.enterpriseiam.audit.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.audit")
public record AuditProperties(Boolean dispatcherEnabled, Duration pollInterval, Integer batchSize,
        Duration leaseDuration, Duration retryBaseDelay, Duration retryMaxDelay,
        Integer retryAlertThreshold, Integer workerCount, Integer queueCapacity) {
    public AuditProperties {
        dispatcherEnabled = dispatcherEnabled == null ? true : dispatcherEnabled;
        pollInterval = duration(pollInterval, Duration.ofSeconds(5), Duration.ofSeconds(1), Duration.ofMinutes(5));
        leaseDuration = duration(leaseDuration, Duration.ofSeconds(60), Duration.ofSeconds(10), Duration.ofMinutes(30));
        retryBaseDelay = duration(retryBaseDelay, Duration.ofSeconds(5), Duration.ofSeconds(1), Duration.ofMinutes(5));
        retryMaxDelay = duration(retryMaxDelay, Duration.ofHours(1), retryBaseDelay, Duration.ofDays(1));
        batchSize = bounded(batchSize, 50, 1, 500);
        retryAlertThreshold = bounded(retryAlertThreshold, 10, 1, 1_000);
        workerCount = bounded(workerCount, 2, 1, 16);
        queueCapacity = bounded(queueCapacity, 32, 1, 1_000);
    }

    private static Duration duration(Duration value, Duration fallback, Duration min, Duration max) {
        Duration chosen = value == null ? fallback : value;
        if (chosen.compareTo(min) < 0 || chosen.compareTo(max) > 0) {
            throw new IllegalArgumentException("Audit duration outside permitted bounds");
        }
        return chosen;
    }

    private static int bounded(Integer value, int fallback, int min, int max) {
        int chosen = value == null ? fallback : value;
        if (chosen < min || chosen > max) {
            throw new IllegalArgumentException("Audit integer outside permitted bounds");
        }
        return chosen;
    }
}
