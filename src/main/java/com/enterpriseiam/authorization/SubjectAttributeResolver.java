package com.enterpriseiam.authorization;

import com.enterpriseiam.security.identity.IamPrincipal;
import com.enterpriseiam.security.identity.IdentityDirectory;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component
public class SubjectAttributeResolver {
    private final IdentityDirectory identities;

    public SubjectAttributeResolver(IdentityDirectory identities) {
        this.identities = identities;
    }

    public IamPrincipal resolve(UUID userId) {
        // Reload active status, assignments and attributes for each decision; JWT claims are not policy.
        return identities.requireActive(userId);
    }
}
