package com.enterpriseiam.security.identity;

import com.enterpriseiam.identity.domain.User;
import java.util.Locale;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class DatabaseUserDetailsService implements UserDetailsService {
    private final IdentityRepository repository;

    public DatabaseUserDetailsService(IdentityRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) {
        if (email == null || email.length() > 320) {
            throw new UsernameNotFoundException("Invalid authentication");
        }
        try {
            User user = repository.findByEmail(email.trim().toLowerCase(Locale.ROOT))
                    .orElseThrow(() -> new UsernameNotFoundException("Invalid authentication"));
            IamPrincipal principal = new IamPrincipal(user.getId(), user.getEmail(), user.getDepartment(),
                    user.getClearanceLevel(), repository.findRoleNames(user.getId()),
                    repository.findPermissionNames(user.getId()));
            return new AccountUserDetails(principal, user.getStatus(), user.getPasswordHash());
        } catch (DataAccessException ex) {
            throw new AuthenticationServiceException("Identity store unavailable", ex);
        }
    }
}
