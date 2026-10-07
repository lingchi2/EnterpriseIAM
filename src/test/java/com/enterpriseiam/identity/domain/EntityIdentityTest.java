package com.enterpriseiam.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.proxy.LazyInitializer;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class EntityIdentityTest {

    @Test
    void assigningAnIdentifierPreservesSetMembershipAndDistinctTransientEntities() {
        Role first = Role.create("READER");
        Role second = Role.create("READER");
        Set<Role> roles = new HashSet<>();
        roles.add(first);
        roles.add(second);

        assertThat(roles).hasSize(2);
        int hashBeforePersistence = first.hashCode();
        UUID identifier = UUID.randomUUID();
        ReflectionTestUtils.setField(first, "id", identifier);

        assertThat(first.hashCode()).isEqualTo(hashBeforePersistence);
        assertThat(roles).contains(first, second);
        assertThat(roles.remove(first)).isTrue();
        assertThat(roles).containsExactly(second);

        Role detached = Role.create("READER");
        ReflectionTestUtils.setField(detached, "id", identifier);
        assertThat(first).isEqualTo(detached);
        assertThat(first.hashCode()).isEqualTo(detached.hashCode());

        Permission differentType = Permission.create("READER");
        ReflectionTestUtils.setField(differentType, "id", identifier);
        assertThat(first).isNotEqualTo(differentType);
    }

    @Test
    void equalityHashingAndDiagnosticsDoNotInitializeAProxy() {
        UUID identifier = UUID.randomUUID();
        User entity = User.register("reader@example.com", "{bcrypt}encoded", "Engineering", (short) 1);
        ReflectionTestUtils.setField(entity, "id", identifier);
        LazyInitializer initializer = mock(LazyInitializer.class);
        doReturn(User.class).when(initializer).getPersistentClass();
        when(initializer.getInternalIdentifier()).thenReturn(identifier);
        User proxy = new UninitializedUserProxy(initializer);

        assertThat(entity).isEqualTo(proxy);
        assertThat(proxy).isEqualTo(entity);
        assertThat(proxy.hashCode()).isEqualTo(entity.hashCode());
        assertThat(proxy.toString()).isEqualTo(entity.toString());
        verify(initializer, never()).initialize();
        verify(initializer, never()).getImplementation();
        verify(initializer, never()).getIdentifier();
    }

    /** Simulates a Hibernate subclass whose inherited fields have not been loaded. */
    private static final class UninitializedUserProxy extends User implements HibernateProxy {
        private final LazyInitializer initializer;

        private UninitializedUserProxy(LazyInitializer initializer) {
            this.initializer = initializer;
        }

        @Override
        public LazyInitializer getHibernateLazyInitializer() {
            return initializer;
        }

        @Override
        public Object writeReplace() {
            return this;
        }

        @Override
        public UUID getId() {
            throw new AssertionError("A proxy getter must not be invoked for identity comparison");
        }
    }
}
