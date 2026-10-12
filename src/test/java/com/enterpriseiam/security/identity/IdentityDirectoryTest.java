package com.enterpriseiam.security.identity;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.enterpriseiam.identity.domain.UserStatus;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;

class IdentityDirectoryTest {
    private final IdentityRepository repository = mock(IdentityRepository.class);
    private final IdentityDirectory directory = new IdentityDirectory(repository);

    @Test
    void currentGrantsAreReloadedAndPermissionNamesCannotImpersonateRoles() {
        UUID id = UUID.randomUUID();
        when(repository.findAttributes(id)).thenReturn(Optional.of(
                new AccountAttributes(id, "a@example.com", UserStatus.ACTIVE, "Finance", (short) 2)));
        when(repository.findRoleNames(id)).thenReturn(Set.of("READER"));
        when(repository.findPermissionNames(id)).thenReturn(Set.of("ROLE_ADMIN", "RESOURCE:READ"))
                .thenReturn(Set.of());
        IamPrincipal first = directory.requireActive(id);
        assertThat(first.authorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_READER", "PERM_ROLE_ADMIN", "PERM_RESOURCE:READ")
                .doesNotContain("ROLE_ADMIN");
        assertThat(directory.requireActive(id).permissions()).isEmpty();
        assertThatThrownBy(() -> first.permissions().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void disabledMissingAndUnavailableAccountsNeverAuthenticate() {
        UUID id = UUID.randomUUID();
        when(repository.findAttributes(id)).thenReturn(Optional.empty()).thenReturn(Optional.of(
                new AccountAttributes(id, "a@example.com", UserStatus.DISABLED, "Finance", (short) 2)));
        assertThatThrownBy(() -> directory.requireActive(id)).isInstanceOf(BadCredentialsException.class);
        assertThatThrownBy(() -> directory.requireActive(id)).isInstanceOf(BadCredentialsException.class);
        verify(repository, never()).findRoleNames(any());
        when(repository.findAttributes(id)).thenThrow(new DataAccessResourceFailureException("offline"));
        assertThatThrownBy(() -> directory.requireActive(id)).isInstanceOf(AuthenticationServiceException.class);
    }

    @Test
    void loginCredentialsCanBeErasedAndDoNotAppearInDiagnostics() {
        IamPrincipal principal = new IamPrincipal(UUID.randomUUID(), "a@example.com", "Finance",
                (short) 2, Set.of(), Set.of());
        AccountUserDetails details = new AccountUserDetails(principal, UserStatus.ACTIVE, "{bcrypt}secret");
        assertThat(details.toString()).doesNotContain("secret", "a@example.com");
        details.eraseCredentials();
        assertThat(details.getPassword()).isNull();
    }
}
