package com.enterpriseiam.authorization;

import com.enterpriseiam.resource.ResourceReference;
import com.enterpriseiam.resource.SecuredResource;
import com.enterpriseiam.security.identity.IamPrincipal;
import java.io.Serializable;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class AbacPermissionEvaluator implements PermissionEvaluator {
    private final SubjectAttributeResolver subjects;
    private final ResourceAttributeResolver resources;
    private final EnvironmentAttributeResolver environments;
    private final AbacPolicy policy;

    public AbacPermissionEvaluator(SubjectAttributeResolver subjects, ResourceAttributeResolver resources,
            EnvironmentAttributeResolver environments, AbacPolicy policy) {
        this.subjects = subjects;
        this.resources = resources;
        this.environments = environments;
        this.policy = policy;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object target, Object permission) {
        UUID id = switch (target) {
            case ResourceReference reference -> reference.id();
            case SecuredResource entity -> entity.getId();
            case null, default -> null;
        };
        return evaluate(authentication, id, permission);
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId,
            String targetType, Object permission) {
        return "RESOURCE".equals(targetType) && targetId instanceof UUID id
                && evaluate(authentication, id, permission);
    }

    private boolean evaluate(Authentication authentication, UUID id, Object permission) {
        if (id == null || authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken
                || !(authentication.getPrincipal() instanceof IamPrincipal principal)
                || !(permission instanceof String name)) {
            return false;
        }
        ResourceAction action;
        try {
            action = ResourceAction.valueOf(name);
        } catch (IllegalArgumentException exception) {
            return false;
        }
        try {
            // Lock contention can outlast a policy boundary or an account/grant change.
            // Acquire authoritative resource state first, then read subject and time attributes.
            var resource = resources.resolve(id, action);
            if (resource.isEmpty()) {
                return false;
            }
            IamPrincipal current = subjects.resolve(principal.userId());
            if (!current.permissions().contains(action.requiredPermission())) {
                return false;
            }
            var environment = environments.resolve();
            if (environment.isEmpty()) {
                return false;
            }
            // This decision is the authorization boundary: subsequent subject/policy changes apply
            // to the next invocation; the resource row remains locked through this operation.
            return policy.permits(current, resource.get(), environment.get(), action);
        } catch (AuthenticationServiceException exception) {
            // Infrastructure failures remain distinguishable from legitimate access denial (HTTP 503).
            throw exception;
        } catch (AuthenticationException exception) {
            return false;
        } catch (DataAccessException exception) {
            throw new AuthenticationServiceException("Authorization data is unavailable", exception);
        }
    }
}
