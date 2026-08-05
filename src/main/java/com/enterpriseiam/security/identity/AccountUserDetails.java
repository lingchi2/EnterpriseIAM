package com.enterpriseiam.security.identity;

import com.enterpriseiam.identity.domain.UserStatus;
import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Collection;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/** Short-lived login material; ProviderManager erases the encoded credential after login. */
public final class AccountUserDetails implements UserDetails, CredentialsContainer {
    private final IamPrincipal principal;
    private final UserStatus status;
    private String passwordHash;

    public AccountUserDetails(IamPrincipal principal, UserStatus status, String passwordHash) {
        this.principal = principal;
        this.status = status;
        this.passwordHash = passwordHash;
    }

    public IamPrincipal principal() { return principal; }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { return principal.authorities(); }

    @Override
    @JsonIgnore
    public String getPassword() { return passwordHash; }

    @Override
    public String getUsername() { return principal.email(); }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return status != UserStatus.LOCKED; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return status == UserStatus.ACTIVE; }

    @Override
    public void eraseCredentials() { passwordHash = null; }

    @Override
    public String toString() { return "AccountUserDetails[userId=" + principal.userId() + "]"; }
}
