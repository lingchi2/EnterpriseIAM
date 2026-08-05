package com.enterpriseiam.security.identity;

import com.enterpriseiam.identity.domain.UserStatus;
import java.util.UUID;

/** The bearer-authentication query deliberately does not select the password column. */
public record AccountAttributes(UUID id, String email, UserStatus status,
        String department, short clearanceLevel) {
    @Override
    public String toString() {
        return "AccountAttributes[id=" + id + "]";
    }
}
