package com.ioc.security.rbac.admin;

import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.model.EffectivePermissions;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.spring.RbacService;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Authorisation for the admin API, including privilege-escalation protection: nobody can hand out (to a role or,
 * through an assignment, to a subject) a permission they do not hold themselves in that scope. Super admins are
 * exempt.
 */
public class RbacAdminGuard {

    private final RbacService rbacService;
    private final RbacAdministration administration;
    private final RbacAdminApiProperties properties;

    public RbacAdminGuard(RbacService rbacService, RbacAdministration administration,
                          RbacAdminApiProperties properties) {
        this.rbacService = rbacService;
        this.administration = administration;
        this.properties = properties;
    }

    /** Current subject; throws when unauthenticated. */
    public String caller() {
        return rbacService.currentSubjectId()
                .orElseThrow(() -> new AuthenticationCredentialsNotFoundException("Authentication is required"));
    }

    public void requireRead() {
        caller();
        rbacService.checkPermission(properties.getReadPermission());
    }

    /** Role / permission definitions are global, so managing them needs the manage permission globally. */
    public EffectivePermissions requireGlobalManage() {
        return requireManage(null);
    }

    /** Assignments are tenant scoped: managing them needs the manage permission in the assignment's tenant. */
    public EffectivePermissions requireManage(String tenantId) {
        EffectivePermissions caller = rbacService.permissionsOf(caller(), tenantId);
        if (!rbacService.hasPermission(caller, properties.getManagePermission())) {
            throw new AccessDeniedException("Requires permission " + properties.getManagePermission()
                    + (tenantId == null ? " (global)" : " in tenant " + tenantId));
        }
        return caller;
    }

    /** Ensures the caller holds every permission it is about to grant. */
    public void requireCanGrant(EffectivePermissions caller, Collection<String> permissions) {
        if (rbacService.isSuperAdmin(caller)) {
            return;
        }
        Set<String> missing = new TreeSet<>();
        for (String permission : permissions) {
            if (!rbacService.hasPermission(caller, permission)) {
                missing.add(permission);
            }
        }
        if (!missing.isEmpty()) {
            throw new AccessDeniedException("Cannot grant permissions you do not hold: " + missing);
        }
    }

    /**
     * Ensures the caller holds every permission the role (including its ancestors) grants. The super-admin role, and
     * any role inheriting from it, can only be handed out by super admins.
     */
    public void requireCanGrantRole(EffectivePermissions caller, String roleName) {
        if (roleName == null || rbacService.isSuperAdmin(caller)) {
            return;
        }
        Set<String> permissions = new HashSet<>();
        Set<String> visited = new HashSet<>();
        String current = roleName;
        while (current != null && visited.add(current)) {
            if (current.equals(rbacService.superAdminRole())) {
                throw new AccessDeniedException("Only super admins can grant " + current);
            }
            Role role = administration.getRole(current);
            permissions.addAll(role.permissions());
            current = role.parentName();
        }
        requireCanGrant(caller, permissions);
    }

    public List<String> nullSafe(Collection<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
