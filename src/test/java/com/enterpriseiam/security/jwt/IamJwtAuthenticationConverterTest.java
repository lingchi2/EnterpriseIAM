package com.enterpriseiam.security.jwt;

import static com.enterpriseiam.security.jwt.JwtTestSupport.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import com.enterpriseiam.security.identity.IdentityDirectory;
import com.enterpriseiam.security.identity.IamPrincipal;
import com.enterpriseiam.security.redis.AccessTokenBlacklist;
import com.enterpriseiam.security.tokens.SessionRegistry;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.jwt.Jwt;

class IamJwtAuthenticationConverterTest {
    private final IdentityDirectory identities = mock(IdentityDirectory.class);
    private final SessionRegistry sessions = mock(SessionRegistry.class);
    private final AccessTokenBlacklist blacklist = mock(AccessTokenBlacklist.class);
    private final IamJwtAuthenticationConverter converter = new IamJwtAuthenticationConverter(identities, sessions, blacklist);
    private final Jwt jwt = DECODER.decode(signed(builder -> {}));

    @Test
    void resolvesCurrentAccountAttributesAndAuthoritiesForEveryAuthentication() {
        IamPrincipal first = new IamPrincipal(USER_ID, "user@example.test", "Finance", (short) 2,
                Set.of("ANALYST"), Set.of("RESOURCE:READ"));
        IamPrincipal changed = new IamPrincipal(USER_ID, "user@example.test", "Finance", (short) 1,
                Set.of(), Set.of());
        when(sessions.isActive(USER_ID, SESSION_ID)).thenReturn(true);
        when(identities.requireActive(USER_ID)).thenReturn(first, changed);
        IamJwtAuthenticationToken authenticated = converter.convert(jwt);
        assertThat(authenticated.getPrincipal()).isEqualTo(first);
        assertThat(authenticated.getToken()).isSameAs(jwt);
        assertThat(authenticated.getCredentials()).isEqualTo("");
        assertThat(converter.convert(jwt).getPrincipal()).isEqualTo(changed);
        verify(identities, times(2)).requireActive(USER_ID);
    }

    @Test
    void refusesRevokedTokenBeforeLoadingAccountOrSession() {
        when(blacklist.isRevoked(TOKEN_ID)).thenReturn(true);
        assertThatThrownBy(() -> converter.convert(jwt)).isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(sessions, identities);
    }

    @Test
    void refusesRevokedOrExpiredSession() {
        when(sessions.isActive(USER_ID, SESSION_ID)).thenReturn(false);
        assertThatThrownBy(() -> converter.convert(jwt)).isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(identities);
    }

    @Test
    void neverAllowsARequestWhenBlacklistIsUnavailable() {
        when(blacklist.isRevoked(TOKEN_ID)).thenThrow(new AuthenticationServiceException("Redis unavailable"));
        assertThatThrownBy(() -> converter.convert(jwt)).isInstanceOf(AuthenticationServiceException.class);
        verifyNoInteractions(sessions, identities);
    }

    @Test
    void refusesDisabledAccountEvenWithValidSignedTokenAndSession() {
        when(sessions.isActive(USER_ID, SESSION_ID)).thenReturn(true);
        when(identities.requireActive(USER_ID)).thenThrow(new BadCredentialsException("Invalid credentials"));
        assertThatThrownBy(() -> converter.convert(jwt)).isInstanceOf(BadCredentialsException.class);
    }
}
