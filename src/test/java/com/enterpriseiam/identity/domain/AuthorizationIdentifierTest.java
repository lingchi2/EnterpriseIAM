package com.enterpriseiam.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class AuthorizationIdentifierTest {

    @Test
    void canonicalIdentifiersAreUnambiguousAcrossRoleAndPermissionNamespaces() {
        assertThat(Role.create("  security_admin  ").getName()).isEqualTo("SECURITY_ADMIN");
        assertThat(Permission.create("  resource:read  ").getName()).isEqualTo("RESOURCE:READ");
        assertThat(Permission.create("AUDIT:EVENT:READ").getName()).isEqualTo("AUDIT:EVENT:READ");
        assertThatIllegalArgumentException().isThrownBy(() -> Role.create("A".repeat(65)));
        assertThatIllegalArgumentException().isThrownBy(() -> Permission.create("A".repeat(129)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "1_ADMIN", "ROLE-ADMIN", "ROLE.ADMIN", "USER:READ", "ROLE ADMIN"})
    void invalidRoleNamesAreRejected(String invalidName) {
        assertThatIllegalArgumentException().isThrownBy(() -> Role.create(invalidName));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", ":READ", "USER:", "USER::READ", "USER:*", "USER:1READ", "USER:READ ALL"})
    void invalidPermissionNamesAreRejected(String invalidName) {
        assertThatIllegalArgumentException().isThrownBy(() -> Permission.create(invalidName));
    }
}
