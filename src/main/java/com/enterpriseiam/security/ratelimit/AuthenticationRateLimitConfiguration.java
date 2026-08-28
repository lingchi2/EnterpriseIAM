package com.enterpriseiam.security.ratelimit;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AuthenticationRateLimitProperties.class)
public class AuthenticationRateLimitConfiguration { }
