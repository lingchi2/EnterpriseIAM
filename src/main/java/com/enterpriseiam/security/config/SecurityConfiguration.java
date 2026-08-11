package com.enterpriseiam.security.config;

import com.enterpriseiam.api.web.RequestBodyLimitFilter;
import com.enterpriseiam.security.jwt.IamJwtAuthenticationConverter;
import com.enterpriseiam.security.ratelimit.AuthenticationRateLimitFilter;
import com.enterpriseiam.security.web.SecurityProblemSupport;
import jakarta.servlet.DispatcherType;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.HttpMethod;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.transaction.TransactionException;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfiguration {
    @Bean
    public PasswordEncoder passwordEncoder() {
        Pbkdf2PasswordEncoder pbkdf2 = new Pbkdf2PasswordEncoder("", 16, 600_000,
                Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);
        // The versioned id allows future upgrades; bcrypt exists only to verify legacy hashes.
        return new DelegatingPasswordEncoder("pbkdf2-sha256",
                Map.of("pbkdf2-sha256", pbkdf2, "bcrypt", new BCryptPasswordEncoder(12)));
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService users, PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(encoder);
        provider.setUserDetailsService(users);
        provider.setHideUserNotFoundExceptions(true);
        // Do the expensive password verification before reporting account state. Otherwise locked/disabled
        // accounts return immediately while unknown accounts execute the provider's dummy password check.
        provider.setPreAuthenticationChecks(user -> { });
        provider.setPostAuthenticationChecks(new AccountStatusUserDetailsChecker());
        ProviderManager delegate = new ProviderManager(provider);
        delegate.setEraseCredentialsAfterAuthentication(true);
        return authentication -> {
            try {
                return delegate.authenticate(authentication);
            } catch (AuthenticationServiceException unavailable) {
                throw unavailable;
            } catch (DataAccessException | TransactionException unavailable) {
                throw new AuthenticationServiceException("Authentication dependency unavailable", unavailable);
            } catch (IllegalArgumentException unsupportedStoredCredential) {
                // Imported hashes with an unknown id or malformed encoding must never become a 500 response.
                throw new BadCredentialsException("Invalid credentials");
            } catch (AuthenticationException rejected) {
                // The external response cannot distinguish unknown, locked, disabled, or wrong-password accounts.
                throw new BadCredentialsException("Invalid credentials");
            }
        };
    }

    @Bean
    public FilterRegistrationBean<AuthenticationRateLimitFilter> rateLimitFilterRegistration(
            AuthenticationRateLimitFilter filter) {
        FilterRegistrationBean<AuthenticationRateLimitFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false); // Runs exactly once, inside Spring Security's filter chain.
        return registration;
    }

    @Bean
    public FilterRegistrationBean<RequestBodyLimitFilter> bodyLimitFilterRegistration(RequestBodyLimitFilter filter) {
        FilterRegistrationBean<RequestBodyLimitFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder decoder,
            IamJwtAuthenticationConverter converter, SecurityProblemSupport problems,
            AuthenticationRateLimitFilter rateLimitFilter, RequestBodyLimitFilter bodyLimitFilter) throws Exception {
        DefaultBearerTokenResolver bearerTokens = new DefaultBearerTokenResolver();
        bearerTokens.setAllowFormEncodedBodyParameter(false);
        bearerTokens.setAllowUriQueryParameter(false);
        http
                .addFilterBefore(rateLimitFilter, BearerTokenAuthenticationFilter.class)
                .addFilterBefore(bodyLimitFilter, AuthenticationRateLimitFilter.class)
                // Only Authorization headers authenticate requests. Cookie authentication must add CSRF protection.
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()))
                .requestCache(cache -> cache.requestCache(new NullRequestCache()))
                .authorizeHttpRequests(authorize -> authorize
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login", "/api/v1/auth/refresh").permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/health/liveness", "/actuator/health/readiness").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().denyAll())
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(problems).accessDeniedHandler(problems))
                .oauth2ResourceServer(oauth -> oauth.bearerTokenResolver(bearerTokens)
                        .authenticationEntryPoint(problems).accessDeniedHandler(problems)
                        .jwt(jwt -> jwt.decoder(decoder).jwtAuthenticationConverter(converter))
                        .withObjectPostProcessor(new ObjectPostProcessor<BearerTokenAuthenticationFilter>() {
                            @Override
                            public <O extends BearerTokenAuthenticationFilter> O postProcess(O filter) {
                                // The default failure handler rethrows service failures, bypassing RFC 7807 responses.
                                filter.setAuthenticationFailureHandler(problems::commence);
                                return filter;
                            }
                        }));
        return http.build();
    }
}
