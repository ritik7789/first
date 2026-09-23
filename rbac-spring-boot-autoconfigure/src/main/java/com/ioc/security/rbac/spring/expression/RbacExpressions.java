package com.ioc.security.rbac.spring.expression;

import com.ioc.security.rbac.spring.RbacService;

/**
 * Registered as bean {@code rbac} for use in SpEL, e.g.
 * {@code @PreAuthorize("@rbac.hasPermission('booking:cancel')")}.
 */
public class RbacExpressions {

    private final RbacService rbacService;

    public RbacExpressions(RbacService rbacService) {
        this.rbacService = rbacService;
    }

    public boolean hasPermission(String permission) {
        return rbacService.hasPermission(permission);
    }

    public boolean hasAnyPermission(String... permissions) {
        return rbacService.hasAnyPermission(permissions);
    }

    public boolean hasAllPermissions(String... permissions) {
        return rbacService.hasAllPermissions(permissions);
    }

    public boolean hasRole(String role) {
        return rbacService.hasRole(role);
    }

    public boolean hasAnyRole(String... roles) {
        return rbacService.hasAnyRole(roles);
    }
}
