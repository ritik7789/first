package com.ioc.security.rbac.core.store;

import com.ioc.security.rbac.core.model.Permission;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import com.ioc.security.rbac.core.spi.RbacManagementStore;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Thread-safe, non persistent store. Used when no database store is configured, for tests and for applications
 * that define their roles purely in configuration ({@code rbac.seed.*}).
 */
public class InMemoryRbacStore implements RbacManagementStore {

    private final Map<String, Permission> permissions = new ConcurrentHashMap<>();
    private final Map<String, Role> roles = new ConcurrentHashMap<>();
    private final Map<String, List<RoleAssignment>> assignments = new ConcurrentHashMap<>();

    @Override
    public Optional<Role> findRole(String roleName) {
        return Optional.ofNullable(roles.get(roleName));
    }

    @Override
    public List<Role> findAllRoles() {
        return roles.values().stream().sorted(Comparator.comparing(Role::name)).toList();
    }

    @Override
    public Optional<Permission> findPermission(String code) {
        return Optional.ofNullable(permissions.get(code));
    }

    @Override
    public List<Permission> findAllPermissions() {
        return permissions.values().stream().sorted(Comparator.comparing(Permission::code)).toList();
    }

    @Override
    public List<RoleAssignment> findAssignments(String subjectId) {
        return List.copyOf(assignments.getOrDefault(subjectId, List.of()));
    }

    @Override
    public synchronized void insertPermission(Permission permission) {
        permissions.put(permission.code(), permission);
    }

    @Override
    public synchronized void deletePermission(String code) {
        permissions.remove(code);
        roles.replaceAll((name, role) -> {
            Set<String> remaining = new HashSet<>(role.permissions());
            remaining.remove(code);
            return role.withPermissions(remaining);
        });
    }

    @Override
    public synchronized void insertRole(Role role) {
        roles.put(role.name(), role);
    }

    @Override
    public synchronized void updateRole(Role role) {
        Role existing = roles.get(role.name());
        roles.put(role.name(), new Role(role.name(), role.description(), role.parentName(),
                existing == null ? role.permissions() : existing.permissions()));
    }

    @Override
    public synchronized void deleteRole(String roleName) {
        roles.remove(roleName);
        assignments.replaceAll((subject, list) ->
                list.stream().filter(a -> !a.roleName().equals(roleName)).toList());
    }

    @Override
    public synchronized void addRolePermissions(String roleName, Collection<String> permissionCodes) {
        Role role = roles.get(roleName);
        Set<String> merged = new HashSet<>(role.permissions());
        merged.addAll(permissionCodes);
        roles.put(roleName, role.withPermissions(merged));
    }

    @Override
    public synchronized void removeRolePermission(String roleName, String permissionCode) {
        Role role = roles.get(roleName);
        Set<String> remaining = new HashSet<>(role.permissions());
        remaining.remove(permissionCode);
        roles.put(roleName, role.withPermissions(remaining));
    }

    @Override
    public synchronized void saveAssignment(RoleAssignment assignment) {
        List<RoleAssignment> list = new ArrayList<>(assignments.getOrDefault(assignment.subjectId(), List.of()));
        list.removeIf(a -> sameKey(a, assignment.subjectId(), assignment.roleName(), assignment.tenantId()));
        list.add(assignment);
        assignments.put(assignment.subjectId(), List.copyOf(list));
    }

    @Override
    public synchronized boolean deleteAssignment(String subjectId, String roleName, String tenantId) {
        List<RoleAssignment> list = new ArrayList<>(assignments.getOrDefault(subjectId, List.of()));
        boolean removed = list.removeIf(a -> sameKey(a, subjectId, roleName, tenantId));
        assignments.put(subjectId, List.copyOf(list));
        return removed;
    }

    @Override
    public List<RoleAssignment> findAssignmentsByRole(String roleName) {
        return assignments.values().stream()
                .flatMap(List::stream)
                .filter(a -> a.roleName().equals(roleName))
                .toList();
    }

    @Override
    public synchronized <T> T inTransaction(Supplier<T> work) {
        return work.get();
    }

    private static boolean sameKey(RoleAssignment a, String subjectId, String roleName, String tenantId) {
        return a.subjectId().equals(subjectId) && a.roleName().equals(roleName)
                && Objects.equals(a.tenantId(), tenantId);
    }
}
