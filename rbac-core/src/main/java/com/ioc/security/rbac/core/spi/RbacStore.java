package com.ioc.security.rbac.core.spi;

import com.ioc.security.rbac.core.model.Permission;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;

import java.util.List;
import java.util.Optional;

/**
 * Read side of RBAC persistence. This is the only interface the decision engine needs, so a host application
 * that keeps roles elsewhere (existing tables, an identity provider, a remote service) only has to implement this.
 */
public interface RbacStore {

    Optional<Role> findRole(String roleName);

    List<Role> findAllRoles();

    Optional<Permission> findPermission(String code);

    List<Permission> findAllPermissions();

    /**
     * All assignments of the subject in every tenant, including expired ones; filtering is done by the engine.
     */
    List<RoleAssignment> findAssignments(String subjectId);
}
