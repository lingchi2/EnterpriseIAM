package com.enterpriseiam.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/** Resource transactions enclose audit advice (50) and method-security advice (200). */
@Configuration(proxyBeanMethods = false)
@EnableTransactionManagement(order = 0)
public class TransactionConfiguration {
}
