package com.ioc.security.rbac.core.engine;

import com.ioc.security.rbac.core.model.EffectivePermissions;
import com.ioc.security.rbac.core.model.Identifiers;
import com.ioc.security.rbac.core.spi.PermissionMatcher;

import java.util.Collection;

/**
 * Pure decision logic over {@link EffectivePermissions}. Holders of the optional super-admin role pass every check.
 */
public class AccessEvaluator {

    private final PermissionMatcher matcher;
    private final String superAdminRole;

    public AccessEvaluator(PermissionMatcher matcher, String superAdminRole) {
        this.matcher = matcher;
        this.superAdminRole = superAdminRole == null || superAdminRole.isBlank() ? null : superAdminRole;
    }

    public boolean isSuperAdmin(EffectivePermissions effective) {
        return superAdminRole != null && effective.roles().contains(superAdminRole);
    }

    public boolean hasPermission(EffectivePermissions effective, String required) {
        if (isSuperAdmin(effective)) {
            return true;
        }
        String normalised = Identifiers.permissionCode(required);
        for (String granted : effective.permissions()) {
            if (matcher.implies(granted, normalised)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasAllPermissions(EffectivePermissions effective, Collection<String> required) {
        return required.stream().allMatch(p -> hasPermission(effective, p));
    }

    public boolean hasAnyPermission(EffectivePermissions effective, Collection<String> required) {
        return required.stream().anyMatch(p -> hasPermission(effective, p));
    }

    public boolean hasRole(EffectivePermissions effective, String role) {
        return isSuperAdmin(effective) || effective.roles().contains(role);
    }

    public boolean hasAllRoles(EffectivePermissions effective, Collection<String> roles) {
        return roles.stream().allMatch(r -> hasRole(effective, r));
    }

    public boolean hasAnyRole(EffectivePermissions effective, Collection<String> roles) {
        return roles.stream().anyMatch(r -> hasRole(effective, r));
    }

    /**
     * Whether holding {@code effective} is enough to hand out {@code permission} to someone else. A granted
     * wildcard can only be delegated by someone whose own permissions imply that same wildcard.
     */
    public boolean canDelegate(EffectivePermissions effective, String permission) {
        return hasPermission(effective, permission);
    }

    /** The configured super-admin role, or {@code null}. */
    public String superAdminRole() {
        return superAdminRole;
    }

    public PermissionMatcher matcher() {
        return matcher;
    }
}
