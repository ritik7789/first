package com.ioc.security.rbac.core.engine;

import com.ioc.security.rbac.core.RbacConflictException;
import com.ioc.security.rbac.core.RbacNotFoundException;
import com.ioc.security.rbac.core.RbacValidationException;
import com.ioc.security.rbac.core.model.Identifiers;
import com.ioc.security.rbac.core.model.Permission;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import com.ioc.security.rbac.core.spi.RbacChangeListener;
import com.ioc.security.rbac.core.spi.RbacChangeListener.ChangeType;
import com.ioc.security.rbac.core.spi.RbacManagementStore;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Validated management operations on roles, permissions and assignments. All writes should go through this class
 * so that invariants hold for every store implementation and listeners (cache eviction, audit) are notified.
 *
 * <p>This class does not check who is calling; the admin REST API adds authorisation and anti-escalation checks.
 */
public class RbacAdministration {

    private final RbacManagementStore store;
    private final Clock clock;
    private final List<RbacChangeListener> listeners = new CopyOnWriteArrayList<>();

    public RbacAdministration(RbacManagementStore store) {
        this(store, Clock.systemUTC());
    }

    public RbacAdministration(RbacManagementStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    public void addListener(RbacChangeListener listener) {
        listeners.add(Objects.requireNonNull(listener));
    }

    // ---------------------------------------------------------------- queries

    public List<Permission> listPermissions() {
        return store.findAllPermissions();
    }

    public Permission getPermission(String code) {
        String normalised = Identifiers.permissionCode(code);
        return store.findPermission(normalised)
                .orElseThrow(() -> new RbacNotFoundException("Permission not found: " + normalised));
    }

    public List<Role> listRoles() {
        return store.findAllRoles();
    }

    public Role getRole(String name) {
        String roleName = Identifiers.roleName(name);
        return store.findRole(roleName).orElseThrow(() -> new RbacNotFoundException("Role not found: " + roleName));
    }

    public List<RoleAssignment> getAssignments(String subjectId) {
        return store.findAssignments(Identifiers.subjectId(subjectId));
    }

    public List<RoleAssignment> getAssignmentsByRole(String roleName) {
        return store.findAssignmentsByRole(getRole(roleName).name());
    }

    // ---------------------------------------------------------------- permissions

    public Permission createPermission(Permission permission) {
        store.inTransaction(() -> {
            if (store.findPermission(permission.code()).isPresent()) {
                throw new RbacConflictException("Permission already exists: " + permission.code());
            }
            store.insertPermission(permission);
            return null;
        });
        notify(ChangeType.PERMISSION_CREATED, permission.code(), null);
        return permission;
    }

    public void deletePermission(String code) {
        String normalised = getPermission(code).code();
        store.inTransaction(() -> {
            store.deletePermission(normalised);
            return null;
        });
        notify(ChangeType.PERMISSION_DELETED, normalised, null);
    }

    // ---------------------------------------------------------------- roles

    /**
     * Creates a role. The parent must exist. Permissions must exist unless {@code createMissingPermissions}.
     */
    public Role createRole(Role role, boolean createMissingPermissions) {
        store.inTransaction(() -> {
            if (store.findRole(role.name()).isPresent()) {
                throw new RbacConflictException("Role already exists: " + role.name());
            }
            requireParent(role.name(), role.parentName());
            ensurePermissionsExist(role.permissions(), createMissingPermissions);
            store.insertRole(role);
            return null;
        });
        notify(ChangeType.ROLE_CREATED, role.name(), null);
        return role;
    }

    /**
     * Updates description and parent of an existing role. Rejects hierarchy cycles.
     */
    public Role updateRole(String name, String description, String parentName) {
        Role updated = store.inTransaction(() -> {
            Role existing = getRole(name);
            Role candidate = new Role(existing.name(), description, parentName, existing.permissions());
            requireParent(candidate.name(), candidate.parentName());
            store.updateRole(candidate);
            return candidate;
        });
        notify(ChangeType.ROLE_UPDATED, updated.name(), null);
        return updated;
    }

    public void deleteRole(String name) {
        String roleName = store.inTransaction(() -> {
            Role role = getRole(name);
            List<String> children = store.findAllRoles().stream()
                    .filter(r -> role.name().equals(r.parentName()))
                    .map(Role::name)
                    .toList();
            if (!children.isEmpty()) {
                throw new RbacConflictException("Role " + role.name() + " is the parent of " + children
                        + "; change their parent first");
            }
            store.deleteRole(role.name());
            return role.name();
        });
        notify(ChangeType.ROLE_DELETED, roleName, null);
    }

    public Role addPermissionsToRole(String name, Collection<String> codes, boolean createMissingPermissions) {
        Set<String> normalised = normalise(codes);
        Role result = store.inTransaction(() -> {
            Role role = getRole(name);
            ensurePermissionsExist(normalised, createMissingPermissions);
            Set<String> missing = new LinkedHashSet<>(normalised);
            missing.removeAll(role.permissions());
            if (!missing.isEmpty()) {
                store.addRolePermissions(role.name(), missing);
            }
            return getRole(role.name());
        });
        notify(ChangeType.ROLE_PERMISSIONS_ADDED, result.name(), String.join(",", normalised));
        return result;
    }

    public Role removePermissionFromRole(String name, String code) {
        String normalised = Identifiers.permissionCode(code);
        Role result = store.inTransaction(() -> {
            Role role = getRole(name);
            if (!role.permissions().contains(normalised)) {
                throw new RbacNotFoundException("Role " + role.name() + " does not have permission " + normalised);
            }
            store.removeRolePermission(role.name(), normalised);
            return getRole(role.name());
        });
        notify(ChangeType.ROLE_PERMISSION_REMOVED, result.name(), normalised);
        return result;
    }

    // ---------------------------------------------------------------- assignments

    public RoleAssignment assignRole(RoleAssignment assignment) {
        Instant now = clock.instant();
        if (assignment.expiresAt() != null && !assignment.expiresAt().isAfter(now)) {
            throw new RbacValidationException("expiresAt must be in the future");
        }
        RoleAssignment stored = new RoleAssignment(assignment.subjectId(), assignment.roleName(),
                assignment.tenantId(), assignment.expiresAt(), assignment.grantedBy(),
                assignment.grantedAt() != null ? assignment.grantedAt() : now);
        store.inTransaction(() -> {
            getRole(stored.roleName());
            store.saveAssignment(stored);
            return null;
        });
        notify(ChangeType.ROLE_ASSIGNED, stored.subjectId(), stored.roleName());
        return stored;
    }

    public void revokeRole(String subjectId, String roleName, String tenantId) {
        String subject = Identifiers.subjectId(subjectId);
        String role = Identifiers.roleName(roleName);
        String tenant = Identifiers.tenantId(tenantId);
        boolean removed = store.inTransaction(() -> store.deleteAssignment(subject, role, tenant));
        if (!removed) {
            throw new RbacNotFoundException("Subject " + subject + " has no assignment of role " + role
                    + (tenant == null ? " (global)" : " in tenant " + tenant));
        }
        notify(ChangeType.ROLE_REVOKED, subject, role);
    }

    // ---------------------------------------------------------------- idempotent helpers (seeding / migration)

    /** Creates the permission if it does not exist yet. */
    public void ensurePermission(Permission permission) {
        if (store.findPermission(permission.code()).isEmpty()) {
            createPermission(permission);
        }
    }

    /**
     * Creates the role if missing, otherwise adds any missing permissions. Existing description, parent and
     * permissions are never removed, so repeated application start-ups do not undo changes made at runtime.
     */
    public void ensureRole(Role role) {
        var existing = store.findRole(role.name());
        if (existing.isEmpty()) {
            createRole(role, true);
        } else if (!existing.get().permissions().containsAll(role.permissions())) {
            addPermissionsToRole(role.name(), role.permissions(), true);
        }
    }

    /** Creates the assignment if the subject does not already hold the role in that tenant. */
    public void ensureAssignment(RoleAssignment assignment) {
        boolean present = store.findAssignments(assignment.subjectId()).stream()
                .anyMatch(a -> a.roleName().equals(assignment.roleName())
                        && Objects.equals(a.tenantId(), assignment.tenantId()));
        if (!present) {
            assignRole(assignment);
        }
    }

    // ---------------------------------------------------------------- internals

    private void requireParent(String roleName, String parentName) {
        if (parentName == null) {
            return;
        }
        Set<String> visited = new HashSet<>();
        String current = parentName;
        while (current != null) {
            if (current.equals(roleName)) {
                throw new RbacValidationException("Setting parent " + parentName + " on role " + roleName
                        + " would create a cycle in the role hierarchy");
            }
            if (!visited.add(current)) {
                break;
            }
            String lookup = current;
            Role parent = store.findRole(lookup)
                    .orElseThrow(() -> new RbacNotFoundException("Parent role not found: " + lookup));
            current = parent.parentName();
        }
    }

    private void ensurePermissionsExist(Collection<String> codes, boolean createMissing) {
        for (String code : codes) {
            if (store.findPermission(code).isEmpty()) {
                if (!createMissing) {
                    throw new RbacNotFoundException("Permission not found: " + code);
                }
                store.insertPermission(Permission.of(code));
            }
        }
    }

    private static Set<String> normalise(Collection<String> codes) {
        if (codes == null || codes.isEmpty()) {
            throw new RbacValidationException("At least one permission code is required");
        }
        Set<String> result = new LinkedHashSet<>();
        for (String code : codes) {
            result.add(Identifiers.permissionCode(code));
        }
        return result;
    }

    private void notify(ChangeType type, String target, String detail) {
        for (RbacChangeListener listener : listeners) {
            listener.onChange(type, target, detail);
        }
    }
}
