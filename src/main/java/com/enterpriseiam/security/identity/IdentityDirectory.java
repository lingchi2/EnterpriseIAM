package com.enterpriseiam.security.identity;

import com.enterpriseiam.identity.domain.UserStatus;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class IdentityDirectory {
    private final IdentityRepository repository;

    public IdentityDirectory(IdentityRepository repository) {
        this.repository = repository;
    }

    public IamPrincipal requireActive(UUID userId) {
        try {
            AccountAttributes account = repository.findAttributes(userId)
                    .filter(value -> value.status() == UserStatus.ACTIVE)
                    .orElseThrow(() -> new BadCredentialsException("Invalid authentication"));
            return new IamPrincipal(account.id(), account.email(), account.department(),
                    account.clearanceLevel(), repository.findRoleNames(userId),
                    repository.findPermissionNames(userId));
        } catch (DataAccessException ex) {
            throw new AuthenticationServiceException("Identity store unavailable", ex);
        }
    }
}
