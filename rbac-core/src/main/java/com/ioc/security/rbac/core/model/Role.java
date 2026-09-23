package com.ioc.security.rbac.core.model;

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;

/**
 * A named bundle of permissions. A role may inherit all permissions of one parent role.
 *
 * @param name        unique role name, e.g. {@code BOOKING_AGENT}
 * @param description optional description
 * @param parentName  optional parent role whose permissions are inherited
 * @param permissions permission codes granted directly to this role (not including inherited ones)
 */
public record Role(String name, String description, String parentName, Set<String> permissions) {

    public Role {
        name = Identifiers.roleName(name);
        parentName = parentName == null || parentName.isBlank() ? null : Identifiers.roleName(parentName);
        permissions = normalise(permissions);
    }

    public static Role of(String name, String... permissions) {
        return new Role(name, null, null, Set.copyOf(Arrays.asList(permissions)));
    }

    public Role withParent(String parent) {
        return new Role(name, description, parent, permissions);
    }

    public Role withPermissions(Collection<String> newPermissions) {
        return new Role(name, description, parentName, Set.copyOf(newPermissions));
    }

    private static Set<String> normalise(Collection<String> codes) {
        Set<String> result = new TreeSet<>();
        if (codes != null) {
            for (String code : codes) {
                result.add(Identifiers.permissionCode(code));
            }
        }
        return Set.copyOf(result);
    }
}
