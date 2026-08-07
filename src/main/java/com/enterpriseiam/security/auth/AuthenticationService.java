package com.enterpriseiam.security.auth;

import com.enterpriseiam.audit.annotation.AuditAction;
import com.enterpriseiam.security.identity.AccountUserDetails;
import com.enterpriseiam.security.jwt.AccessTokenService;
import com.enterpriseiam.security.jwt.IamJwtAuthenticationToken;
import com.enterpriseiam.security.jwt.IssuedAccessToken;
import com.enterpriseiam.security.redis.AccessTokenBlacklist;
import com.enterpriseiam.security.tokens.IssuedRefreshToken;
import com.enterpriseiam.security.tokens.RefreshTokenService;
import java.util.UUID;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

/** Coordinates login/session creation without wrapping replay revocation in a caller transaction. */
@Service
public class AuthenticationService {
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokens;
    private final AccessTokenService accessTokens;
    private final AccessTokenBlacklist blacklist;

    public AuthenticationService(AuthenticationManager authenticationManager,
            RefreshTokenService refreshTokens, AccessTokenService accessTokens,
            AccessTokenBlacklist blacklist) {
        this.authenticationManager = authenticationManager;
        this.refreshTokens = refreshTokens;
        this.accessTokens = accessTokens;
        this.blacklist = blacklist;
    }

    @AuditAction(action = "AUTH_LOGIN")
    public TokenPair login(String email, String password) {
        // Bound credentials before invoking the deliberately expensive password encoder.
        if (email == null || email.isBlank() || email.length() > 320
                || password == null || password.isEmpty() || password.length() > 1024) {
            throw new BadCredentialsException("Invalid credentials");
        }
        UsernamePasswordAuthenticationToken request =
                UsernamePasswordAuthenticationToken.unauthenticated(email, password);
        try {
            Authentication authenticated = authenticationManager.authenticate(request);
            if (!(authenticated.getPrincipal() instanceof AccountUserDetails account)
                    || !authenticated.isAuthenticated()) {
                throw new AuthenticationServiceException("Unexpected authentication provider result");
            }
            return issuePair(refreshTokens.create(account.principal().userId()));
        } finally {
            request.eraseCredentials();
        }
    }

    @AuditAction(action = "AUTH_REFRESH")
    public TokenPair refresh(String rawRefreshToken) {
        return issuePair(refreshTokens.rotate(rawRefreshToken));
    }

    /** Revoke the entire current session, including access tokens issued before its last refresh. */
    @AuditAction(action = "AUTH_LOGOUT")
    public void logout(IamJwtAuthenticationToken authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new BadCredentialsException("Invalid authentication");
        }
        Jwt token = authentication.getToken();
        UUID userId = authentication.getPrincipal().userId();
        UUID sessionId = UUID.fromString(token.getClaimAsString("sid"));
        // Database revocation commits first and survives a Redis outage. No success is reported on outage.
        refreshTokens.revokeSession(userId, sessionId);
        blacklist.revoke(UUID.fromString(token.getId()), token.getExpiresAt());
    }

    private TokenPair issuePair(IssuedRefreshToken refresh) {
        try {
            IssuedAccessToken access = accessTokens.issue(refresh.userId(), refresh.sessionId());
            return new TokenPair(access.token(), refresh.rawToken(), access.expiresAt(), refresh.expiresAt());
        } catch (RuntimeException issuanceFailure) {
            // A signing failure must not leave an undisclosed live session behind.
            try {
                refreshTokens.revokeSession(refresh.userId(), refresh.sessionId());
            } catch (RuntimeException revocationFailure) {
                issuanceFailure.addSuppressed(revocationFailure);
            }
            throw new AuthenticationServiceException("Token issuance unavailable", issuanceFailure);
        }
    }
}
