package com.ioc.security.rbac.test;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Set;

/**
 * Authentication created by {@link WithRbacUser}; carries the RBAC grants to use instead of the store.
 */
public class RbacTestAuthentication extends AbstractAuthenticationToken {

    private final String subjectId;
    private final Set<String> roles;
    private final Set<String> permissions;

    public RbacTestAuthentication(String subjectId, Set<String> roles, Set<String> permissions) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.subjectId = subjectId;
        this.roles = Set.copyOf(roles);
        this.permissions = Set.copyOf(permissions);
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return subjectId;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public Set<String> getPermissions() {
        return permissions;
    }
}
