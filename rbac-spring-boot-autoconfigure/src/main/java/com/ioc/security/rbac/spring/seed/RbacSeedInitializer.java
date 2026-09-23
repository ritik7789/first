package com.ioc.security.rbac.spring.seed;

import com.ioc.security.rbac.autoconfigure.RbacProperties;
import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.model.Permission;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Applies {@code rbac.seed.*} at start-up, before the web server accepts requests. Seeding is additive and
 * idempotent: it never removes or overwrites data changed at runtime.
 */
public class RbacSeedInitializer implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(RbacSeedInitializer.class);

    private final RbacAdministration administration;
    private final RbacProperties.Seed seed;

    public RbacSeedInitializer(RbacAdministration administration, RbacProperties.Seed seed) {
        this.administration = administration;
        this.seed = seed;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (seed.getPermissions().isEmpty() && seed.getRoles().isEmpty() && seed.getAssignments().isEmpty()) {
            return;
        }
        seed.getPermissions().forEach((code, description) ->
                administration.ensurePermission(new Permission(code, description)));
        for (Map.Entry<String, RbacProperties.RoleSeed> entry : parentsFirst(seed.getRoles()).entrySet()) {
            RbacProperties.RoleSeed role = entry.getValue();
            administration.ensureRole(new Role(entry.getKey(), role.getDescription(), role.getParent(),
                    role.getPermissions()));
        }
        for (RbacProperties.AssignmentSeed assignment : seed.getAssignments()) {
            administration.ensureAssignment(RoleAssignment.forTenant(assignment.getSubject(), assignment.getRole(),
                    assignment.getTenant()));
        }
        log.info("RBAC seed applied: {} permissions, {} roles, {} assignments", seed.getPermissions().size(),
                seed.getRoles().size(), seed.getAssignments().size());
    }

    /**
     * Orders roles so that a parent is created before its children, regardless of declaration order.
     */
    static Map<String, RbacProperties.RoleSeed> parentsFirst(Map<String, RbacProperties.RoleSeed> roles) {
        Map<String, RbacProperties.RoleSeed> ordered = new LinkedHashMap<>();
        Map<String, RbacProperties.RoleSeed> remaining = new HashMap<>(roles);
        List<String> names = new ArrayList<>(roles.keySet());
        while (!remaining.isEmpty()) {
            boolean progressed = false;
            for (String name : names) {
                RbacProperties.RoleSeed role = remaining.get(name);
                if (role == null) {
                    continue;
                }
                String parent = role.getParent();
                if (parent == null || parent.isBlank() || ordered.containsKey(parent) || !roles.containsKey(parent)) {
                    ordered.put(name, role);
                    remaining.remove(name);
                    progressed = true;
                }
            }
            if (!progressed) {
                throw new IllegalStateException("rbac.seed.roles contains a parent cycle among " + remaining.keySet());
            }
        }
        return ordered;
    }
}
