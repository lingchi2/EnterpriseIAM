package com.enterpriseiam.security.jwt;

import com.enterpriseiam.security.identity.IdentityDirectory;
import com.enterpriseiam.security.identity.IamPrincipal;
import com.enterpriseiam.security.redis.AccessTokenBlacklist;
import com.enterpriseiam.security.tokens.SessionRegistry;
import java.util.UUID;
import org.springframework.core.convert.converter.Converter;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.transaction.TransactionException;

@Component
public final class IamJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private final IdentityDirectory identities;
    private final SessionRegistry sessions;
    private final AccessTokenBlacklist blacklist;

    public IamJwtAuthenticationConverter(IdentityDirectory identities, SessionRegistry sessions,
            AccessTokenBlacklist blacklist) {
        this.identities = identities;
        this.sessions = sessions;
        this.blacklist = blacklist;
    }

    @Override
    public IamJwtAuthenticationToken convert(Jwt jwt) {
        // The decoder validates the UUID shape and all required claims before conversion.
        UUID userId = UUID.fromString(jwt.getSubject());
        UUID sessionId = UUID.fromString(jwt.getClaimAsString("sid"));
        UUID tokenId = UUID.fromString(jwt.getId());
        try {
            if (blacklist.isRevoked(tokenId) || !sessions.isActive(userId, sessionId)) {
                throw new BadCredentialsException("Invalid access token");
            }
            IamPrincipal principal = identities.requireActive(userId);
            return new IamJwtAuthenticationToken(jwt, principal);
        } catch (DataAccessException | TransactionException exception) {
            throw new AuthenticationServiceException("Authentication dependency unavailable", exception);
        }
    }
}
