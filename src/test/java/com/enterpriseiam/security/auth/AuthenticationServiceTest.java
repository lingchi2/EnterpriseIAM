package com.enterpriseiam.security.auth;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.enterpriseiam.identity.domain.UserStatus;
import com.enterpriseiam.security.identity.AccountUserDetails;
import com.enterpriseiam.security.identity.IamPrincipal;
import com.enterpriseiam.security.jwt.AccessTokenService;
import com.enterpriseiam.security.jwt.IamJwtAuthenticationToken;
import com.enterpriseiam.security.jwt.IssuedAccessToken;
import com.enterpriseiam.security.redis.AccessTokenBlacklist;
import com.enterpriseiam.security.tokens.IssuedRefreshToken;
import com.enterpriseiam.security.tokens.RefreshTokenService;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

class AuthenticationServiceTest {
    private final AuthenticationManager manager = mock(AuthenticationManager.class);
    private final RefreshTokenService refresh = mock(RefreshTokenService.class);
    private final AccessTokenService access = mock(AccessTokenService.class);
    private final AccessTokenBlacklist blacklist = mock(AccessTokenBlacklist.class);
    private final AuthenticationService service = new AuthenticationService(manager, refresh, access, blacklist);
    private final UUID user = UUID.randomUUID();
    private final UUID session = UUID.randomUUID();
    private final UUID tokenId = UUID.randomUUID();
    private final Instant expiry = Instant.now().plusSeconds(300);

    @Test
    void failedLoginNeverCreatesASession() {
        when(manager.authenticate(any())).thenThrow(new BadCredentialsException("invalid"));
        assertThatThrownBy(() -> service.login("a@example.com", "wrong"))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(refresh, access, blacklist);
    }

    @Test
    void successfulLoginUsesAuthenticatedIdentityAndRedactsItsResult() {
        AccountUserDetails account = new AccountUserDetails(principal(), UserStatus.ACTIVE, "{bcrypt}hash");
        when(manager.authenticate(any())).thenReturn(
                UsernamePasswordAuthenticationToken.authenticated(account, null, account.getAuthorities()));
        when(refresh.create(user)).thenReturn(new IssuedRefreshToken("refresh-secret", user, session, expiry));
        when(access.issue(user, session)).thenReturn(new IssuedAccessToken("access-secret", tokenId, expiry));
        TokenPair pair = service.login("a@example.com", "correct");
        assertThat(pair.accessToken()).isEqualTo("access-secret");
        assertThat(pair.refreshToken()).isEqualTo("refresh-secret");
        assertThat(pair.toString()).doesNotContain("access-secret", "refresh-secret");
    }

    @Test
    void logoutCommitsFamilyRevocationBeforeAttemptingRedis() {
        Jwt jwt = Jwt.withTokenValue("secret").header("alg", "RS256").subject(user.toString())
                .claim("sid", session.toString()).claim("jti", tokenId.toString()).expiresAt(expiry)
                .issuedAt(expiry.minusSeconds(300)).build();
        doThrow(new AuthenticationServiceException("offline")).when(blacklist).revoke(tokenId, expiry);
        assertThatThrownBy(() -> service.logout(new IamJwtAuthenticationToken(jwt, principal())))
                .isInstanceOf(AuthenticationServiceException.class);
        var ordered = inOrder(refresh, blacklist);
        ordered.verify(refresh).revokeSession(user, session);
        ordered.verify(blacklist).revoke(tokenId, expiry);
    }

    @Test
    void signingFailureRevokesTheNewSession() {
        when(refresh.rotate("token")).thenReturn(new IssuedRefreshToken("new-token", user, session, expiry));
        when(access.issue(user, session)).thenThrow(new IllegalStateException("signer failure"));
        assertThatThrownBy(() -> service.refresh("token")).isInstanceOf(AuthenticationServiceException.class);
        verify(refresh).revokeSession(user, session);
    }

    private IamPrincipal principal() {
        return new IamPrincipal(user, "a@example.com", "Finance", (short) 2, Set.of(), Set.of());
    }
}
