package com.ioc.security.rbac.core.model;

import java.util.Set;

/**
 * The fully resolved authorisation state of a subject in a tenant: all roles (including inherited parents)
 * and all permissions granted by those roles.
 */
public record EffectivePermissions(String subjectId, String tenantId, Set<String> roles, Set<String> permissions) {

    public EffectivePermissions {
        roles = Set.copyOf(roles);
        permissions = Set.copyOf(permissions);
    }

    public static EffectivePermissions none(String subjectId, String tenantId) {
        return new EffectivePermissions(subjectId, tenantId, Set.of(), Set.of());
    }
}
