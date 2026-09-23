package com.ioc.security.rbac.core.model;

import java.time.Instant;

/**
 * Grants a role to a subject (user, service account, ...).
 *
 * @param subjectId identifier of the subject as known to the host application (username, UUID, JWT {@code sub}, ...)
 * @param roleName  role being granted
 * @param tenantId  tenant the grant is limited to, or {@code null} for a global grant valid in every tenant
 * @param expiresAt optional instant after which the grant is ignored
 * @param grantedBy optional subject id of whoever made the grant (audit)
 * @param grantedAt optional instant of the grant (audit)
 */
public record RoleAssignment(String subjectId, String roleName, String tenantId, Instant expiresAt,
                             String grantedBy, Instant grantedAt) {

    public RoleAssignment {
        subjectId = Identifiers.subjectId(subjectId);
        roleName = Identifiers.roleName(roleName);
        tenantId = Identifiers.tenantId(tenantId);
    }

    public static RoleAssignment global(String subjectId, String roleName) {
        return new RoleAssignment(subjectId, roleName, null, null, null, null);
    }

    public static RoleAssignment forTenant(String subjectId, String roleName, String tenantId) {
        return new RoleAssignment(subjectId, roleName, tenantId, null, null, null);
    }

    public boolean isGlobal() {
        return tenantId == null;
    }

    public boolean isActive(Instant now) {
        return expiresAt == null || expiresAt.isAfter(now);
    }

    /**
     * Whether this assignment applies when the caller acts in {@code requestTenant}.
     * Global assignments apply to every tenant; tenant assignments only to their own tenant.
     */
    public boolean appliesTo(String requestTenant) {
        return tenantId == null || tenantId.equals(requestTenant);
    }
}
