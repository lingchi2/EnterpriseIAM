package com.enterpriseiam.security.tokens;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(TokenProperties.class)
class TokenConfiguration {
}
