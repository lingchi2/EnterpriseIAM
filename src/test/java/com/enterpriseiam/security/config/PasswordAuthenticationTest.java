package com.enterpriseiam.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.CannotCreateTransactionException;

class PasswordAuthenticationTest {
    private final SecurityConfiguration configuration = new SecurityConfiguration();
    private final PasswordEncoder encoder = configuration.passwordEncoder();

    @Test
    void producesVersionedSaltedPbkdf2AndErasesLoginCredentials() {
        String hash = encoder.encode("a long unique passphrase");
        assertThat(hash).startsWith("{pbkdf2-sha256}");
        assertThat(encoder.matches("a long unique passphrase", hash)).isTrue();
        assertThat(encoder.matches("wrong", hash)).isFalse();
        UserDetailsService users = name -> User.withUsername(name).password(hash).authorities("ROLE_ANALYST").build();
        Authentication authenticated = configuration.authenticationManager(users, encoder)
                .authenticate(UsernamePasswordAuthenticationToken.unauthenticated("user@example.test", "a long unique passphrase"));
        assertThat(authenticated.isAuthenticated()).isTrue();
        assertThat(authenticated.getCredentials()).isNull();
        assertThat(((User) authenticated.getPrincipal()).getPassword()).isNull();
    }

    @Test
    void hidesAbsentDisabledLockedAndIncorrectAccounts() {
        String hash = encoder.encode("valid passphrase");
        UserDetailsService users = name -> switch (name) {
            case "missing" -> throw new UsernameNotFoundException("secret account details");
            case "disabled" -> User.withUsername(name).password(hash).authorities("ROLE_ANALYST").disabled(true).build();
            case "locked" -> User.withUsername(name).password(hash).authorities("ROLE_ANALYST").accountLocked(true).build();
            default -> User.withUsername(name).password(hash).authorities("ROLE_ANALYST").build();
        };
        AuthenticationManager manager = configuration.authenticationManager(users, encoder);
        for (String name : new String[]{"missing", "disabled", "locked", "active"}) {
            assertThatThrownBy(() -> manager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(name, "incorrect")))
                    .isExactlyInstanceOf(BadCredentialsException.class).hasMessage("Invalid credentials");
        }
    }

    @Test
    void preservesDependencyFailureAsServiceUnavailable() {
        UserDetailsService users = name -> { throw new AuthenticationServiceException("Database unavailable"); };
        assertThatThrownBy(() -> configuration.authenticationManager(users, encoder).authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated("user@example.test", "password")))
                .isInstanceOf(AuthenticationServiceException.class);
    }

    @Test
    void doesNotAcceptNoopOrUnversionedPasswords() {
        assertThatThrownBy(() -> encoder.matches("password", "{noop}password"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> encoder.matches("password", "password"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void transactionStartupFailureIsAnAuthenticationDependencyFailure() {
        UserDetailsService users = name -> { throw new CannotCreateTransactionException("Database connection unavailable"); };
        assertThatThrownBy(() -> configuration.authenticationManager(users, encoder).authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated("user@example.test", "password")))
                .isInstanceOf(AuthenticationServiceException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"{unsupported}historical-hash", "{pbkdf2-sha256}malformed", "{noop}password"})
    void unsupportedOrMalformedImportedHashesAreGenericInvalidCredentials(String storedHash) {
        UserDetailsService users = name -> User.withUsername(name).password(storedHash).authorities("ROLE_ANALYST").build();
        assertThatThrownBy(() -> configuration.authenticationManager(users, encoder).authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated("user@example.test", "password")))
                .isExactlyInstanceOf(BadCredentialsException.class).hasMessage("Invalid credentials");
    }
}
