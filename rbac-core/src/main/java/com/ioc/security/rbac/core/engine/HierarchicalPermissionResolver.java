package com.ioc.security.rbac.core.engine;

import com.ioc.security.rbac.core.model.EffectivePermissions;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import com.ioc.security.rbac.core.spi.PermissionResolver;
import com.ioc.security.rbac.core.spi.RbacStore;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Default resolver: active assignments valid for the tenant, expanded through the role hierarchy.
 * Unknown roles are ignored and hierarchy cycles are tolerated (each role is visited once).
 */
public class HierarchicalPermissionResolver implements PermissionResolver {

    private final RbacStore store;
    private final Clock clock;

    public HierarchicalPermissionResolver(RbacStore store) {
        this(store, Clock.systemUTC());
    }

    public HierarchicalPermissionResolver(RbacStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    @Override
    public EffectivePermissions resolve(String subjectId, String tenantId) {
        if (subjectId == null) {
            return EffectivePermissions.none(null, tenantId);
        }
        Instant now = clock.instant();
        Deque<String> pending = new ArrayDeque<>();
        for (RoleAssignment assignment : store.findAssignments(subjectId)) {
            if (assignment.isActive(now) && assignment.appliesTo(tenantId)) {
                pending.add(assignment.roleName());
            }
        }
        Set<String> roles = new LinkedHashSet<>();
        Set<String> permissions = new TreeSet<>();
        while (!pending.isEmpty()) {
            String roleName = pending.poll();
            if (!roles.add(roleName)) {
                continue;
            }
            Optional<Role> role = store.findRole(roleName);
            if (role.isEmpty()) {
                roles.remove(roleName);
                continue;
            }
            permissions.addAll(role.get().permissions());
            if (role.get().parentName() != null) {
                pending.add(role.get().parentName());
            }
        }
        return new EffectivePermissions(subjectId, tenantId, roles, permissions);
    }
}
