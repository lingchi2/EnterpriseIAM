package com.enterpriseiam.security.tokens;

import java.time.Clock;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationServiceException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class SessionRegistryTest {

    @Test
    void databaseOutageFailsClosedWithoutTreatingSessionAsActive() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(anyString(), eq(Boolean.class), any(), any(), any()))
                .thenThrow(new DataAccessResourceFailureException("offline"));
        SessionRegistry registry = new SessionRegistry(jdbc, Clock.systemUTC());
        assertThrows(AuthenticationServiceException.class,
                () -> registry.isActive(UUID.randomUUID(), UUID.randomUUID()));
    }

    @Test
    void missingSessionOrSubjectIsNeverActive() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        SessionRegistry registry = new SessionRegistry(jdbc, Clock.systemUTC());
        assertFalse(registry.isActive(null, UUID.randomUUID()));
        assertFalse(registry.isActive(UUID.randomUUID(), null));
        verifyNoInteractions(jdbc);
    }
}
