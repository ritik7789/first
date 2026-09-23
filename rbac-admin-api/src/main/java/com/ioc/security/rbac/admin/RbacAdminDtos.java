package com.ioc.security.rbac.admin;

import java.time.Instant;
import java.util.Set;

/**
 * Request / response bodies of the admin API.
 */
public final class RbacAdminDtos {

    private RbacAdminDtos() {
    }

    public record PermissionRequest(String code, String description) {
    }

    public record RoleRequest(String name, String description, String parent, Set<String> permissions) {
    }

    public record RoleUpdateRequest(String description, String parent) {
    }

    public record PermissionCodesRequest(Set<String> permissions) {
    }

    public record AssignmentRequest(String role, String tenantId, Instant expiresAt) {
    }

    public record EffectivePermissionsResponse(String subjectId, String tenantId, Set<String> roles,
                                               Set<String> permissions, boolean superAdmin) {
    }
}
