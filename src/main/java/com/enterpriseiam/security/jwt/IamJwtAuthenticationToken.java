package com.enterpriseiam.security.jwt;

import com.enterpriseiam.security.identity.IamPrincipal;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

/** Credentials stay out of logs while the verified JWT remains available for logout/revocation. */
public final class IamJwtAuthenticationToken extends AbstractAuthenticationToken {
    private final IamPrincipal principal;
    private final Jwt token;

    public IamJwtAuthenticationToken(Jwt token, IamPrincipal principal) {
        super(principal.authorities());
        this.principal = principal;
        this.token = token;
        super.setAuthenticated(true);
    }

    @Override public IamPrincipal getPrincipal() { return principal; }
    @Override public Object getCredentials() { return ""; }
    @Override public String getName() { return principal.userId().toString(); }
    public Jwt getToken() { return token; }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Use the verified JWT authentication constructor");
        }
        super.setAuthenticated(false);
    }

    @Override public String toString() { return "IamJwtAuthenticationToken[REDACTED]"; }
}
