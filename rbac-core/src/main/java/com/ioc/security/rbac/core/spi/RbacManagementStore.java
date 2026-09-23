package com.ioc.security.rbac.core.spi;

import com.ioc.security.rbac.core.model.Permission;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;

import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

/**
 * Write side of RBAC persistence. Implementations perform plain data access only; validation (existence checks,
 * hierarchy cycles, ...) is done by {@link com.ioc.security.rbac.core.engine.RbacAdministration}.
 */
public interface RbacManagementStore extends RbacStore {

    void insertPermission(Permission permission);

    /** Deletes the permission and removes it from every role. */
    void deletePermission(String code);

    /** Inserts the role together with its direct permissions. */
    void insertRole(Role role);

    /** Updates description and parent of the role. Permissions are left unchanged. */
    void updateRole(Role role);

    /** Deletes the role, its permission links and its assignments. */
    void deleteRole(String roleName);

    void addRolePermissions(String roleName, Collection<String> permissionCodes);

    void removeRolePermission(String roleName, String permissionCode);

    /** Inserts or replaces the assignment identified by (subject, role, tenant). */
    void saveAssignment(RoleAssignment assignment);

    /** @return {@code true} if an assignment was removed */
    boolean deleteAssignment(String subjectId, String roleName, String tenantId);

    List<RoleAssignment> findAssignmentsByRole(String roleName);

    /**
     * Runs the given work atomically. Stores backed by a transactional resource should override this.
     */
    default <T> T inTransaction(Supplier<T> work) {
        return work.get();
    }
}
