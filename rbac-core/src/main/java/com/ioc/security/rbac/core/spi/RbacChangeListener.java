package com.ioc.security.rbac.core.spi;

/**
 * Notified after RBAC data was changed through {@link com.ioc.security.rbac.core.engine.RbacAdministration}.
 * Used for cache eviction and auditing.
 */
@FunctionalInterface
public interface RbacChangeListener {

    enum ChangeType {
        PERMISSION_CREATED, PERMISSION_DELETED,
        ROLE_CREATED, ROLE_UPDATED, ROLE_DELETED,
        ROLE_PERMISSIONS_ADDED, ROLE_PERMISSION_REMOVED,
        ROLE_ASSIGNED, ROLE_REVOKED
    }

    /**
     * @param type   what changed
     * @param target main object affected (permission code, role name or subject id)
     * @param detail optional additional information (e.g. role name for assignments)
     */
    void onChange(ChangeType type, String target, String detail);
}
