package com.enterpriseiam.authorization;

import com.enterpriseiam.security.identity.IamPrincipal;

/** Replaceable, typed policy boundary. No user-authored expression is evaluated. */
public interface AbacPolicy {
    boolean permits(IamPrincipal subject, ResourceAttributes resource,
            EnvironmentAttributes environment, ResourceAction action);
}
