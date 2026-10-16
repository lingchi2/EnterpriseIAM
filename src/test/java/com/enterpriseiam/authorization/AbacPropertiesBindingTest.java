package com.enterpriseiam.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

class AbacPropertiesBindingTest {
    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfiguration.class);

    @Test
    void absentNetworkConfigurationBindsToAnEmptyAllowlist() {
        context.run(application -> {
            assertThat(application).hasNotFailed();
            assertThat(application.getBean(AbacProperties.class).allowedCidrs()).isEmpty();
            assertThat(application.getBean(AbacProperties.class).zoneId()).isEqualTo("UTC");
        });
    }

    @Test
    void invalidNetworkCausesStartupToFail() {
        context.withPropertyValues("iam.abac.allowed-cidrs=trusted.example.com/24")
                .run(application -> assertThat(application).hasFailed());
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(AbacProperties.class)
    static class PropertiesConfiguration { }
}
