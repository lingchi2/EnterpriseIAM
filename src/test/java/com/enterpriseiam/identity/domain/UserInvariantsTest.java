package com.enterpriseiam.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class UserInvariantsTest {

    @Test
    void registrationCanonicalizesAttributesAndRequiresExplicitActivation() {
        User user = User.register("  Alice@Example.COM  ", "{bcrypt}encoded", "  Engineering  ", (short) 2);

        assertThat(user.getEmail()).isEqualTo("alice@example.com");
        assertThat(user.getDepartment()).isEqualTo("Engineering");
        assertThat(user.getStatus()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        assertThat(user.getClearanceLevel()).isEqualTo((short) 2);
        assertThat(user.getRoles()).isEmpty();
        assertThatIllegalStateException().isThrownBy(user::unlock);

        user.activate();
        user.lock();
        assertThat(user.getStatus()).isEqualTo(UserStatus.LOCKED);
        user.unlock();
        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
        user.disable();
        assertThatIllegalStateException().isThrownBy(user::activate);
        assertThatIllegalStateException().isThrownBy(user::unlock);
        assertThat(user.getStatus()).isEqualTo(UserStatus.DISABLED);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"plain-password", "{noop}plain-password", "{bcrypt}", "{bcrypt}contains space"})
    void invalidCredentialUpdatesLeaveThePreviousHashIntact(String invalidPassword) {
        User user = user();

        assertThatIllegalArgumentException().isThrownBy(() -> user.changePasswordHash(invalidPassword));
        assertThat(user.getPasswordHash()).isEqualTo("{bcrypt}encoded");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "missing-domain@", "@missing-local", "not-an-email", "a@b@c", "a b@example.com"})
    void invalidEmailUpdatesDoNotMutateTheAccount(String invalidEmail) {
        User user = user();

        assertThatIllegalArgumentException().isThrownBy(() -> user.changeEmail(invalidEmail));
        assertThat(user.getEmail()).isEqualTo("alice@example.com");
    }

    @Test
    void invalidAttributeChangesAreAtomic() {
        User user = user();

        assertThatIllegalArgumentException()
                .isThrownBy(() -> user.updateAttributes("Security", (short) 5));
        assertThat(user.getDepartment()).isEqualTo("Engineering");
        assertThat(user.getClearanceLevel()).isEqualTo((short) 2);
        assertThatIllegalArgumentException()
                .isThrownBy(() -> user.updateAttributes("  ", (short) 3));
        assertThat(user.getClearanceLevel()).isEqualTo((short) 2);
    }

    @Test
    void associationViewsCannotBypassControlledMutation() {
        User user = user();
        Role role = Role.create("reader");
        Permission permission = Permission.create("resource:read");
        Set<Role> rolesView = user.getRoles();
        Set<Permission> permissionsView = role.getPermissions();

        assertThat(user.assignRole(role)).isTrue();
        assertThat(user.assignRole(role)).isFalse();
        assertThat(role.grantPermission(permission)).isTrue();
        assertThat(rolesView).containsExactly(role);
        assertThat(permissionsView).containsExactly(permission);
        assertThatThrownBy(rolesView::clear).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(permissionsView::clear).isInstanceOf(UnsupportedOperationException.class);
        assertThat(user.removeRole(role)).isTrue();
        assertThat(role.revokePermission(permission)).isTrue();
        assertThat(rolesView).isEmpty();
        assertThat(permissionsView).isEmpty();
    }

    @Test
    void credentialsAndLazyAssociationsAreAbsentFromJsonAndDiagnostics() throws Exception {
        User user = user();
        Role role = Role.create("ADMIN");
        role.grantPermission(Permission.create("USER:UPDATE"));
        user.assignRole(role);
        ObjectMapper mapper = new ObjectMapper();

        JsonNode accountJson = mapper.readTree(mapper.writeValueAsString(user));
        JsonNode roleJson = mapper.readTree(mapper.writeValueAsString(role));

        assertThat(accountJson.has("passwordHash")).isFalse();
        assertThat(accountJson.has("roles")).isFalse();
        assertThat(roleJson.has("permissions")).isFalse();
        assertThat(user.toString()).doesNotContain("encoded", "alice", "Engineering", "ADMIN");
    }

    @Test
    void storageLimitsAreValidatedBeforePersistence() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> User.register("a".repeat(250) + "@example.com", "{bcrypt}encoded", "Engineering", (short) 0));
        // LATIN CAPITAL I WITH DOT expands to two code points under Locale.ROOT lowercase.
        assertThatIllegalArgumentException().isThrownBy(
                () -> User.register("\u0130".repeat(125) + "@example.com", "{bcrypt}encoded", "Engineering", (short) 0));
        assertThatIllegalArgumentException().isThrownBy(
                () -> User.register("a@example.com", "{bcrypt}" + "a".repeat(255), "Engineering", (short) 0));
        assertThatIllegalArgumentException().isThrownBy(
                () -> User.register("a@example.com", "{bcrypt}encoded", "a".repeat(101), (short) 0));
        assertThatIllegalArgumentException().isThrownBy(
                () -> User.register("a@example.com", "{bcrypt}encoded", "Engineering", (short) -1));
    }

    private static User user() {
        return User.register("alice@example.com", "{bcrypt}encoded", "Engineering", (short) 2);
    }
}
