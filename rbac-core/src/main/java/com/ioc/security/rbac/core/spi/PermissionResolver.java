package com.ioc.security.rbac.core.spi;

import com.ioc.security.rbac.core.model.EffectivePermissions;

/**
 * Computes the effective roles and permissions of a subject acting in a tenant.
 */
@FunctionalInterface
public interface PermissionResolver {

    /**
     * @param subjectId subject identifier
     * @param tenantId  tenant the subject acts in, or {@code null} when multi-tenancy is not used
     */
    EffectivePermissions resolve(String subjectId, String tenantId);
}
